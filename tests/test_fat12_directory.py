#!/usr/bin/env python3

# Copyright (c) 2026 Stephen P Smith
# MIT License

import pytest
from fat12_backend.handler import FAT12Image
from fat12_backend.directory import (
    iter_directory_entries, get_entry_offset, 
    get_existing_83_names_in_directory, find_free_directory_entries,
    free_cluster_chain, FAT12Error, FAT12CorruptionError
)

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def handler(tmp_path):
    """Create a fresh FAT12 image for testing"""
    img_path = tmp_path / "test_dir.img"
    FAT12Image.create_empty_image(str(img_path))
    return FAT12Image(str(img_path))


@pytest.fixture
def populated_handler(handler):
    """Create a handler with some initial files for duplication testing"""
    # Add 2 test files to root
    handler.write_file_to_image("FILE1.TXT", b"Content of file 1" * 10, use_numeric_tail=True)
    handler.write_file_to_image("FILE2.TXT", b"Content of file 2" * 10, use_numeric_tail=True)
    return handler


@pytest.fixture
def nested_structure(handler):
    """
    Create a nested directory structure for testing:
    ROOT/
    ├── LEVEL1/
    │   ├── FILE1.TXT
    │   ├── FILE2.TXT
    │   └── LEVEL2/
    │       ├── DEEP1.TXT
    │       ├── DEEP2.TXT
    │       └── LEVEL3/
    │           └── VERYDEEP.TXT
    """
    # Create level 1
    handler.create_directory("LEVEL1", use_numeric_tail=True)
    root_entries = handler.read_root_directory()
    level1 = next(e for e in root_entries if e['name'] == 'LEVEL1')
    
    # Add files to level 1
    handler.write_file_to_image("FILE1.TXT", b"Level 1 File 1" * 10, 
                               use_numeric_tail=True, parent_cluster=level1['cluster'])
    handler.write_file_to_image("FILE2.TXT", b"Level 1 File 2" * 10, 
                               use_numeric_tail=True, parent_cluster=level1['cluster'])
    
    # Create level 2
    handler.create_directory("LEVEL2", use_numeric_tail=True, parent_cluster=level1['cluster'])
    level1_entries = handler.read_directory(level1['cluster'])
    level2 = next(e for e in level1_entries if e['name'] == 'LEVEL2')
    
    # Add files to level 2
    handler.write_file_to_image("DEEP1.TXT", b"Level 2 File 1" * 10, 
                               use_numeric_tail=True, parent_cluster=level2['cluster'])
    handler.write_file_to_image("DEEP2.TXT", b"Level 2 File 2" * 10, 
                               use_numeric_tail=True, parent_cluster=level2['cluster'])
    
    # Create level 3
    handler.create_directory("LEVEL3", use_numeric_tail=True, parent_cluster=level2['cluster'])
    level2_entries = handler.read_directory(level2['cluster'])
    level3 = next(e for e in level2_entries if e['name'] == 'LEVEL3')
    
    # Add file to level 3
    handler.write_file_to_image("VERYDEEP.TXT", b"Level 3 File" * 10, 
                               use_numeric_tail=True, parent_cluster=level3['cluster'])
    
    return {
        'level1': level1,
        'level2': level2,
        'level3': level3
    }


# =============================================================================
# BASIC DIRECTORY OPERATIONS
# =============================================================================

class TestDirectoryCreation:
    def test_create_directory_root(self, handler):
        handler.create_directory("TESTDIR")
        entries = handler.read_root_directory()
        entry = next((e for e in entries if e['name'] == "TESTDIR"), None)
        assert entry is not None
        assert entry['is_dir']
        assert entry['cluster'] >= 2

    def test_create_nested_directory(self, handler):
        handler.create_directory("PARENT")
        parent = next(e for e in handler.read_root_directory() if e['name'] == "PARENT")
        
        handler.create_directory("CHILD", parent_cluster=parent['cluster'])
        
        sub_entries = handler.read_directory(parent['cluster'])
        child = next((e for e in sub_entries if e['name'] == "CHILD"), None)
        assert child is not None
        assert child['is_dir']


class TestDirectoryDeletion:
    def test_delete_empty_directory(self, handler):
        handler.create_directory("EMPTY")
        entry = next(e for e in handler.read_root_directory() if e['name'] == "EMPTY")
        
        handler.delete_directory(entry)
        
        entries = handler.read_root_directory()
        assert not any(e['name'] == "EMPTY" for e in entries)

    def test_delete_non_empty_directory_fails(self, handler):
        handler.create_directory("FULL")
        entry = next(e for e in handler.read_root_directory() if e['name'] == "FULL")
        
        handler.write_file_to_image("FILE.TXT", b"data", parent_cluster=entry['cluster'])
        
        # Should fail without recursive=True
        with pytest.raises(FAT12Error):
            handler.delete_directory(entry)

    def test_delete_recursive(self, handler):
        handler.create_directory("RECURSIVE")
        entry = next(e for e in handler.read_root_directory() if e['name'] == "RECURSIVE")
        
        handler.write_file_to_image("FILE.TXT", b"data", parent_cluster=entry['cluster'])
        
        handler.delete_directory(entry, recursive=True)
        
        entries = handler.read_root_directory()
        assert not any(e['name'] == "RECURSIVE" for e in entries)


class TestFileOperationsInDirectory:
    def test_write_file_to_subdir(self, handler):
        handler.create_directory("DOCS")
        docs = next(e for e in handler.read_root_directory() if e['name'] == "DOCS")
        
        handler.write_file_to_image("NOTE.TXT", b"content", parent_cluster=docs['cluster'])
        
        sub_entries = handler.read_directory(docs['cluster'])
        file_entry = next((e for e in sub_entries if e['name'] == "NOTE.TXT"), None)
        assert file_entry is not None
        assert file_entry['size'] == 7

    def test_delete_file_in_subdir(self, handler):
        handler.create_directory("TRASH")
        trash = next(e for e in handler.read_root_directory() if e['name'] == "TRASH")
        
        handler.write_file_to_image("JUNK.TXT", b"junk", parent_cluster=trash['cluster'])
        
        sub_entries = handler.read_directory(trash['cluster'])
        junk = next(e for e in sub_entries if e['name'] == "JUNK.TXT")
        
        handler.delete_file(junk)
        
        sub_entries = handler.read_directory(trash['cluster'])
        assert not any(e['name'] == "JUNK.TXT" for e in sub_entries)


# =============================================================================
# DIRECTORY INTERNALS
# =============================================================================

class TestIterDirectoryEntries:
    def test_iter_root_directory(self, handler):
        """Test iterating over the fixed-size root directory"""
        # Write some files to root
        handler.write_file_to_image("FILE1.TXT", b"1")
        handler.write_file_to_image("FILE2.TXT", b"2")
        
        # Iterate
        entries = list(iter_directory_entries(handler, 0))
        
        # Root has 224 entries fixed
        assert len(entries) == 224
        
        # Check first entry (FILE1)
        idx, data = entries[0]
        assert idx == 0
        assert data[:5] == b"FILE1"
        
        # Check second entry (FILE2)
        idx, data = entries[1]
        assert idx == 1
        assert data[:5] == b"FILE2"

    def test_iter_subdirectory_chain(self, handler):
        """Test iterating over a subdirectory that spans multiple clusters"""
        handler.create_directory("SUBDIR")
        entries = handler.read_root_directory()
        subdir_entry = next(e for e in entries if e['name'] == "SUBDIR")
        cluster = subdir_entry['cluster']
        
        # Fill the subdirectory to force a cluster chain extension
        # 1 cluster = 512 bytes = 16 entries. . and .. take 2.
        # Writing 20 files + 2 existing = 22 entries.
        # This requires 2 clusters (capacity 32 entries).
        for i in range(20):
            handler.write_file_to_image(f"F{i}.TXT", b"x", parent_cluster=cluster)
            
        entries = list(iter_directory_entries(handler, cluster))
        
        # Should yield exactly 32 slots (16 * 2 clusters)
        assert len(entries) == 32
        
        # Verify indices are sequential
        indices = [e[0] for e in entries]
        assert indices == list(range(32))


class TestDirectoryInternals:
    def test_get_entry_offset_root(self, handler):
        """Test offset calculation for root directory"""
        # Index 0 should be at root_start
        offset = get_entry_offset(handler, 0, 0)
        assert offset == handler.root_start
        
        # Index 1 should be 32 bytes later
        offset = get_entry_offset(handler, 0, 1)
        assert offset == handler.root_start + 32

    def test_get_entry_offset_subdir(self, handler):
        """Test offset calculation for subdirectory"""
        handler.create_directory("SUB")
        entries = handler.read_root_directory()
        sub = next(e for e in entries if e['name'] == "SUB")
        cluster = sub['cluster']
        
        # Index 0 of subdir should be at start of that cluster's data
        expected_offset = handler.data_start + ((cluster - 2) * handler.bytes_per_cluster)
        offset = get_entry_offset(handler, cluster, 0)
        assert offset == expected_offset
        
        # Index 16 (start of next cluster, if it existed)
        # Since we only have 1 cluster, this should return -1 or handle chain end
        # get_entry_offset returns -1 if chain ends
        with pytest.raises(FAT12CorruptionError):
            get_entry_offset(handler, cluster, 16)

    def test_get_existing_names(self, handler):
        """Test retrieving existing 8.3 names"""
        handler.write_file_to_image("FILE1.TXT", b"")
        handler.write_file_to_image("FILE2.TXT", b"")
        
        names = get_existing_83_names_in_directory(handler, 0)
        assert "FILE1   TXT" in names
        assert "FILE2   TXT" in names
        assert len(names) == 2

    def test_find_free_entries_gaps(self, handler):
        """Test finding free entries with gaps"""
        handler.write_file_to_image("A.TXT", b"")
        handler.write_file_to_image("B.TXT", b"")
        handler.write_file_to_image("C.TXT", b"")
        
        entries = handler.read_root_directory()
        b_entry = next(e for e in entries if e['name'] == "B.TXT")
        
        # Delete B to create a gap at index 1
        handler.delete_file(b_entry)
        
        # Should find index 1
        idx = find_free_directory_entries(handler, 0, 1)
        assert idx == 1

    def test_find_free_entries_expansion(self, handler):
        """Test that finding entries triggers expansion calculation logic"""
        # Note: Actual expansion happens inside find_free_directory_entries if we call it
        # on a full subdirectory.
        handler.create_directory("FULL")
        sub = next(e for e in handler.read_root_directory() if e['name'] == "FULL")
        
        # Fill the first cluster (16 entries). . and .. take 0 and 1.
        # We write 14 files.
        for i in range(14):
            handler.write_file_to_image(f"F{i}.TXT", b"", parent_cluster=sub['cluster'])
            
        # Now the directory is full (16/16 slots used).
        # Requesting 1 more slot should trigger expansion and return index 16.
        idx = find_free_directory_entries(handler, sub['cluster'], 1)
        assert idx == 16
        
        # Verify the directory actually grew (chain length check)
        chain = handler.get_cluster_chain(sub['cluster'])
        assert len(chain) == 2


class TestFreeClusterChain:
    def test_free_simple_chain(self, handler):
        """Test freeing a simple contiguous chain"""
        # 2 -> 3 -> EOF
        fat = handler.read_fat()
        handler.set_fat_entry(fat, 2, 3)
        handler.set_fat_entry(fat, 3, 0xFFF)
        handler.write_fat(fat)
        
        free_cluster_chain(handler, 2)
        
        fat = handler.read_fat()
        assert handler.get_fat_entry(fat, 2) == 0
        assert handler.get_fat_entry(fat, 3) == 0

    def test_free_single_cluster(self, handler):
        """Test freeing a single cluster"""
        # 5 -> EOF
        fat = handler.read_fat()
        handler.set_fat_entry(fat, 5, 0xFFF)
        handler.write_fat(fat)
        
        free_cluster_chain(handler, 5)
        
        fat = handler.read_fat()
        assert handler.get_fat_entry(fat, 5) == 0

    def test_free_fragmented_chain(self, handler):
        """Test freeing a non-contiguous chain"""
        # 2 -> 10 -> 5 -> EOF
        fat = handler.read_fat()
        handler.set_fat_entry(fat, 2, 10)
        handler.set_fat_entry(fat, 10, 5)
        handler.set_fat_entry(fat, 5, 0xFFF)
        handler.write_fat(fat)
        
        free_cluster_chain(handler, 2)
        
        fat = handler.read_fat()
        assert handler.get_fat_entry(fat, 2) == 0
        assert handler.get_fat_entry(fat, 10) == 0
        assert handler.get_fat_entry(fat, 5) == 0

    def test_ignore_reserved_clusters(self, handler):
        """Test that it ignores start_cluster < 2"""
        # Setup cluster 2 as used
        fat = handler.read_fat()
        handler.set_fat_entry(fat, 2, 0xFFF)
        handler.write_fat(fat)
        
        # Try to free 0 and 1
        free_cluster_chain(handler, 0)
        free_cluster_chain(handler, 1)
        
        # Verify 2 is still used (indirect check that nothing weird happened)
        fat = handler.read_fat()
        assert handler.get_fat_entry(fat, 2) == 0xFFF
        # Verify 0 and 1 are unchanged (usually F0 FF FF for 1.44MB)
        assert fat[0] == 0xF0


# =============================================================================
# DUPLICATE FILE CORRUPTION TESTS
# =============================================================================

class TestDuplicateFilesInRoot:
    """
    Test duplicating files in the root directory.
    """
    
    def test_duplicate_single_file_root(self, populated_handler):
        """Test duplicating a single file in root directory (baseline)"""
        # Get the first file
        entries = populated_handler.read_root_directory()
        file1 = next(e for e in entries if e['name'] == 'FILE1.TXT')
        
        # Extract and duplicate
        data = populated_handler.extract_file(file1)
        populated_handler.write_file_to_image("FILE1 - Copy.TXT", data, use_numeric_tail=True)
        
        # Verify both files exist
        entries = populated_handler.read_root_directory()
        assert any(e['name'] == 'FILE1.TXT' for e in entries)
        assert any(e['name'] == 'FILE1 - Copy.TXT' for e in entries)
        
        # Verify data integrity
        file1_copy = next(e for e in entries if e['name'] == 'FILE1 - Copy.TXT')
        copy_data = populated_handler.extract_file(file1_copy)
        assert data == copy_data
    
    def test_duplicate_two_files_root_sequential(self, populated_handler):
        """
        Duplicate 2 files in root directory sequentially.
        """
        # Get both files
        entries = populated_handler.read_root_directory()
        file1 = next(e for e in entries if e['name'] == 'FILE1.TXT')
        file2 = next(e for e in entries if e['name'] == 'FILE2.TXT')
        
        # Extract data
        data1 = populated_handler.extract_file(file1)
        data2 = populated_handler.extract_file(file2)
        
        # Duplicate both files
        populated_handler.write_file_to_image("FILE1 - Copy.TXT", data1, use_numeric_tail=True)
        populated_handler.write_file_to_image("FILE2 - Copy.TXT", data2, use_numeric_tail=True)
        
        # VERIFICATION: Check for corruption
        # 1. All files should exist
        entries_after = populated_handler.read_root_directory()
        expected_files = ['FILE1.TXT', 'FILE2.TXT', 'FILE1 - Copy.TXT', 'FILE2 - Copy.TXT']
        actual_files = [e['name'] for e in entries_after if not e['is_dir']]
        
        for expected in expected_files:
            assert expected in actual_files, f"Missing file: {expected}"
        
        # 2. Verify data integrity of all files
        for entry in entries_after:
            if entry['is_dir']:
                continue
            try:
                extracted = populated_handler.extract_file(entry)
                assert len(extracted) > 0, f"File {entry['name']} has zero length"
                
                # Verify content matches expected
                if 'FILE1' in entry['name']:
                    assert extracted == data1, f"File {entry['name']} data corrupted"
                elif 'FILE2' in entry['name']:
                    assert extracted == data2, f"File {entry['name']} data corrupted"
            except Exception as e:
                pytest.fail(f"Failed to extract {entry['name']}: {e}")
        
        # 3. Verify FAT integrity - no orphaned clusters
        fat_data = populated_handler.read_fat()
        used_clusters = set()
        
        for entry in entries_after:
            if entry.get('cluster', 0) >= 2:
                chain = populated_handler.get_cluster_chain(entry['cluster'])
                for cluster in chain:
                    assert cluster not in used_clusters, f"Cluster {cluster} used by multiple entries"
                    used_clusters.add(cluster)
    
    def test_duplicate_multiple_files_rapid(self, handler):
        """
        Duplicate multiple files in rapid succession.
        This tests for race conditions in cluster allocation.
        """
        # Create 5 files
        for i in range(5):
            handler.write_file_to_image(f"TEST{i}.TXT", f"Content {i}".encode() * 20, 
                                       use_numeric_tail=True)
        
        # Get all files and their data
        entries = handler.read_root_directory()
        files_data = {}
        for entry in entries:
            if entry['name'].startswith('TEST') and not entry['is_dir']:
                files_data[entry['name']] = handler.extract_file(entry)
        
        # Duplicate all 5 files
        for name, data in files_data.items():
            copy_name = name.replace('.TXT', ' - Copy.TXT')
            handler.write_file_to_image(copy_name, data, use_numeric_tail=True)
        
        # Verify all 10 files exist
        entries_after = handler.read_root_directory()
        file_names = [e['name'] for e in entries_after if not e['is_dir']]
        
        # Should have original 5 + 5 copies = 10 files
        assert len(file_names) >= 10, f"Expected at least 10 files, got {len(file_names)}"
        
        # Verify each file's data
        for entry in entries_after:
            if entry['is_dir'] or not entry['name'].startswith('TEST'):
                continue
            
            extracted = handler.extract_file(entry)
            
            # Find original name (remove " - Copy" if present)
            original_name = entry['name'].replace(' - Copy', '')
            expected_data = files_data.get(original_name)
            
            if expected_data:
                assert extracted == expected_data, f"File {entry['name']} data corrupted"


class TestDuplicateFilesInSubdirectory:
    """Test duplicating files in subdirectories"""
    
    def test_duplicate_two_files_subdirectory(self, handler):
        """
        Duplicate 2 files in a subdirectory.
        """
        # Create subdirectory
        handler.create_directory("DUPTEST", use_numeric_tail=True)
        entries = handler.read_root_directory()
        subdir = next(e for e in entries if e['name'] == 'DUPTEST')
        
        # Add 2 files to subdirectory
        handler.write_file_to_image("ALPHA.TXT", b"Alpha content" * 10, 
                                    use_numeric_tail=True, parent_cluster=subdir['cluster'])
        handler.write_file_to_image("BETA.TXT", b"Beta content" * 10, 
                                    use_numeric_tail=True, parent_cluster=subdir['cluster'])
        
        # Get the files
        sub_entries = handler.read_directory(subdir['cluster'])
        alpha = next(e for e in sub_entries if e['name'] == 'ALPHA.TXT')
        beta = next(e for e in sub_entries if e['name'] == 'BETA.TXT')
        
        # Extract data
        data_alpha = handler.extract_file(alpha)
        data_beta = handler.extract_file(beta)
        
        # Duplicate both
        handler.write_file_to_image("ALPHA - Copy.TXT", data_alpha, 
                                    use_numeric_tail=True, parent_cluster=subdir['cluster'])
        handler.write_file_to_image("BETA - Copy.TXT", data_beta, 
                                    use_numeric_tail=True, parent_cluster=subdir['cluster'])
        
        # Verify all files exist and are intact
        sub_entries_after = handler.read_directory(subdir['cluster'])
        expected = ['ALPHA.TXT', 'BETA.TXT', 'ALPHA - Copy.TXT', 'BETA - Copy.TXT']
        actual = [e['name'] for e in sub_entries_after if e['name'] not in ('.', '..')]
        
        for exp in expected:
            assert exp in actual, f"Missing file: {exp}"
        
        # Verify data integrity
        for entry in sub_entries_after:
            if entry['name'] in ('.', '..'):
                continue
            extracted = handler.extract_file(entry)
            assert len(extracted) > 0, f"File {entry['name']} is empty"
            
            if 'ALPHA' in entry['name']:
                assert extracted == data_alpha, f"ALPHA file corrupted: {entry['name']}"
            elif 'BETA' in entry['name']:
                assert extracted == data_beta, f"BETA file corrupted: {entry['name']}"


class TestDirectoryExpansionDuringDuplicate:
    """Test scenarios where directory expansion happens during duplication"""
    
    def test_duplicate_causes_directory_expansion(self, handler):
        """
        Test that duplicating files that cause directory expansion works correctly.
        A subdirectory cluster holds 16 entries (512 bytes / 32 bytes per entry).
        . and .. take 2, so we can fit 14 regular files before needing expansion.
        """
        # Create subdirectory
        handler.create_directory("EXPAND", use_numeric_tail=True)
        entries = handler.read_root_directory()
        subdir = next(e for e in entries if e['name'] == 'EXPAND')
        
        # Add 14 files to fill first cluster (. and .. already there)
        for i in range(14):
            handler.write_file_to_image(f"FILE{i:02d}.TXT", f"Content {i}".encode() * 5, 
                                       use_numeric_tail=True, parent_cluster=subdir['cluster'])
        
        # Verify we have 14 files (+ . and ..)
        sub_entries = handler.read_directory(subdir['cluster'])
        regular_files = [e for e in sub_entries if e['name'] not in ('.', '..')]
        assert len(regular_files) == 14
        
        # Get cluster chain before duplication
        chain_before = handler.get_cluster_chain(subdir['cluster'])
        assert len(chain_before) == 1, "Should start with 1 cluster"
        
        # Now duplicate 2 files - this should trigger expansion
        file0 = next(e for e in sub_entries if e['name'] == 'FILE00.TXT')
        file1 = next(e for e in sub_entries if e['name'] == 'FILE01.TXT')
        
        data0 = handler.extract_file(file0)
        data1 = handler.extract_file(file1)
        
        handler.write_file_to_image("FILE00 - Copy.TXT", data0, 
                                    use_numeric_tail=True, parent_cluster=subdir['cluster'])
        handler.write_file_to_image("FILE01 - Copy.TXT", data1, 
                                    use_numeric_tail=True, parent_cluster=subdir['cluster'])
        
        # Verify directory expanded
        chain_after = handler.get_cluster_chain(subdir['cluster'])
        assert len(chain_after) == 2, f"Directory should have expanded to 2 clusters, got {len(chain_after)}"
        
        # Verify all files are intact
        sub_entries_after = handler.read_directory(subdir['cluster'])
        regular_files_after = [e for e in sub_entries_after if e['name'] not in ('.', '..')]
        assert len(regular_files_after) == 16, f"Should have 16 files after duplication, got {len(regular_files_after)}"
        
        # Verify data integrity of duplicated files
        copy0 = next(e for e in sub_entries_after if e['name'] == 'FILE00 - Copy.TXT')
        copy1 = next(e for e in sub_entries_after if e['name'] == 'FILE01 - Copy.TXT')
        
        assert handler.extract_file(copy0) == data0
        assert handler.extract_file(copy1) == data1


# =============================================================================
# NESTED DIRECTORY DUPLICATION TESTS
# =============================================================================

class TestDuplicateInNestedDirectories:
    """Test duplicating files in nested directories - critical bug scenarios"""
    
    def test_duplicate_two_files_level1(self, nested_structure, handler):
        """
        Duplicate 2 files in first-level subdirectory
        """
        level1 = nested_structure['level1']
        
        # Get both files
        entries = handler.read_directory(level1['cluster'])
        file1 = next(e for e in entries if e['name'] == 'FILE1.TXT')
        file2 = next(e for e in entries if e['name'] == 'FILE2.TXT')
        
        # Extract data
        data1 = handler.extract_file(file1)
        data2 = handler.extract_file(file2)
        
        # Duplicate both files
        handler.write_file_to_image("FILE1 - Copy.TXT", data1, 
                                    use_numeric_tail=True, parent_cluster=level1['cluster'])
        handler.write_file_to_image("FILE2 - Copy.TXT", data2, 
                                    use_numeric_tail=True, parent_cluster=level1['cluster'])
        
        # Verify all 4 files exist
        entries_after = handler.read_directory(level1['cluster'])
        names = [e['name'] for e in entries_after if e['name'] not in ('.', '..')]
        
        assert 'FILE1.TXT' in names
        assert 'FILE2.TXT' in names
        assert 'FILE1 - Copy.TXT' in names
        assert 'FILE2 - Copy.TXT' in names
        assert 'LEVEL2' in names  # Subdirectory should still exist
        
        # Verify data integrity
        copy1 = next(e for e in entries_after if e['name'] == 'FILE1 - Copy.TXT')
        copy2 = next(e for e in entries_after if e['name'] == 'FILE2 - Copy.TXT')
        
        assert handler.extract_file(copy1) == data1
        assert handler.extract_file(copy2) == data2
        
        # Verify subdirectory still accessible
        level2_check = next(e for e in entries_after if e['name'] == 'LEVEL2')
        level2_entries = handler.read_directory(level2_check['cluster'])
        assert any(e['name'] == 'DEEP1.TXT' for e in level2_entries)
    
    def test_duplicate_two_files_level2(self, nested_structure, handler):
        """
        Duplicate 2 files in second-level subdirectory
        This tests parent_cluster tracking through multiple levels
        """
        level2 = nested_structure['level2']
        
        # Get both files
        entries = handler.read_directory(level2['cluster'])
        deep1 = next(e for e in entries if e['name'] == 'DEEP1.TXT')
        deep2 = next(e for e in entries if e['name'] == 'DEEP2.TXT')
        
        # Extract data
        data1 = handler.extract_file(deep1)
        data2 = handler.extract_file(deep2)
        
        # Duplicate both files
        handler.write_file_to_image("DEEP1 - Copy.TXT", data1, 
                                    use_numeric_tail=True, parent_cluster=level2['cluster'])
        handler.write_file_to_image("DEEP2 - Copy.TXT", data2, 
                                    use_numeric_tail=True, parent_cluster=level2['cluster'])
        
        # Verify all files exist
        entries_after = handler.read_directory(level2['cluster'])
        names = [e['name'] for e in entries_after if e['name'] not in ('.', '..')]
        
        expected = ['DEEP1.TXT', 'DEEP2.TXT', 'DEEP1 - Copy.TXT', 
                   'DEEP2 - Copy.TXT', 'LEVEL3']
        for exp in expected:
            assert exp in names, f"Missing: {exp}"
        
        # Verify data integrity
        copy1 = next(e for e in entries_after if e['name'] == 'DEEP1 - Copy.TXT')
        copy2 = next(e for e in entries_after if e['name'] == 'DEEP2 - Copy.TXT')
        
        assert handler.extract_file(copy1) == data1
        assert handler.extract_file(copy2) == data2
        
        # Verify level 3 subdirectory still accessible
        level3_check = next(e for e in entries_after if e['name'] == 'LEVEL3')
        level3_entries = handler.read_directory(level3_check['cluster'])
        assert any(e['name'] == 'VERYDEEP.TXT' for e in level3_entries)
    
    def test_duplicate_expansion_preserves_parent_access(self, handler):
        """
        Verify that expanding a nested directory doesn't corrupt parent access
        """
        # Create parent/child structure
        handler.create_directory("PARENT", use_numeric_tail=True)
        root = handler.read_root_directory()
        parent = next(e for e in root if e['name'] == 'PARENT')
        
        # Add a file to parent
        handler.write_file_to_image("PARENT_FILE.TXT", b"Parent data" * 10,
                                    use_numeric_tail=True, parent_cluster=parent['cluster'])
        
        handler.create_directory("CHILD", use_numeric_tail=True, parent_cluster=parent['cluster'])
        parent_entries = handler.read_directory(parent['cluster'])
        child = next(e for e in parent_entries if e['name'] == 'CHILD')
        
        # Fill and expand child
        for i in range(14):
            handler.write_file_to_image(f"F{i}.TXT", f"D{i}".encode() * 3,
                                       use_numeric_tail=True, parent_cluster=child['cluster'])
        
        # Duplicate to trigger expansion
        child_entries = handler.read_directory(child['cluster'])
        f0 = next(e for e in child_entries if e['name'] == 'F0.TXT')
        f1 = next(e for e in child_entries if e['name'] == 'F1.TXT')
        
        d0 = handler.extract_file(f0)
        d1 = handler.extract_file(f1)
        
        handler.write_file_to_image("C0.TXT", d0, use_numeric_tail=True, parent_cluster=child['cluster'])
        handler.write_file_to_image("C1.TXT", d1, use_numeric_tail=True, parent_cluster=child['cluster'])
        
        # CRITICAL: Verify parent is still accessible and intact
        parent_entries_after = handler.read_directory(parent['cluster'])
        
        # Parent should still have the original file
        assert any(e['name'] == 'PARENT_FILE.TXT' for e in parent_entries_after)
        
        # Parent should still have child directory reference
        child_ref = next(e for e in parent_entries_after if e['name'] == 'CHILD')
        assert child_ref['cluster'] == child['cluster']
        
        # Verify parent file data intact
        parent_file = next(e for e in parent_entries_after if e['name'] == 'PARENT_FILE.TXT')
        parent_data = handler.extract_file(parent_file)
        assert parent_data == b"Parent data" * 10


class TestNestedFATIntegrity:
    """Test FAT integrity with nested directory operations"""
    
    def test_no_cluster_leaks_nested_duplicate(self, nested_structure, handler):
        """Verify no cluster leaks when duplicating in nested directories"""
        level1 = nested_structure['level1']
        level2 = nested_structure['level2']
        
        # Duplicate in both levels
        l1_entries = handler.read_directory(level1['cluster'])
        l2_entries = handler.read_directory(level2['cluster'])
        
        l1_file = next(e for e in l1_entries if e['name'] == 'FILE1.TXT')
        l2_file = next(e for e in l2_entries if e['name'] == 'DEEP1.TXT')
        
        l1_data = handler.extract_file(l1_file)
        l2_data = handler.extract_file(l2_file)
        
        handler.write_file_to_image("DUP1.TXT", l1_data, 
                                    use_numeric_tail=True, parent_cluster=level1['cluster'])
        handler.write_file_to_image("DUP2.TXT", l2_data, 
                                    use_numeric_tail=True, parent_cluster=level2['cluster'])
        
        # Check for orphaned clusters
        fat_data = handler.read_fat()
        
        # Collect all referenced clusters recursively
        referenced = set()
        
        def collect(cluster):
            if cluster is None or cluster == 0:
                entries = handler.read_root_directory()
            else:
                entries = handler.read_directory(cluster)
            
            for entry in entries:
                if entry.get('cluster', 0) >= 2:
                    chain = handler.get_cluster_chain(entry['cluster'])
                    referenced.update(chain)
                    
                if entry.get('is_dir', False) and entry.get('name') not in ('.', '..'):
                    collect(entry['cluster'])
        
        collect(None)
        
        # Check for orphaned
        orphaned = []
        for cluster in range(2, handler.total_clusters):
            fat_entry = handler.get_fat_entry(fat_data, cluster)
            if fat_entry != 0 and fat_entry != 0xFF7 and cluster not in referenced:
                orphaned.append(cluster)
        
        assert len(orphaned) == 0, f"Orphaned clusters: {orphaned}"
