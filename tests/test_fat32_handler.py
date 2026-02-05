import pytest
from fat12_handler import FAT12Image

@pytest.fixture
def handler():
    # Create instance without running full __init__ to test methods in isolation
    return FAT12Image.__new__(FAT12Image)

def test_fat12_bit_packing(handler):
    # FAT12 stores two 12-bit entries (1.5 bytes each) across 3 bytes
    fat_buffer = bytearray(10)
    
    # Set Cluster 2 to 0xABC and Cluster 3 to 0x123
    handler.set_fat_entry(fat_buffer, 2, 0xABC)
    handler.set_fat_entry(fat_buffer, 3, 0x123)
    
    # Verify values are retrieved correctly despite being packed
    assert handler.get_fat_entry(fat_buffer, 2) == 0xABC
    assert handler.get_fat_entry(fat_buffer, 3) == 0x123

def test_boot_sector_initialization(tmp_path):
    # Create a temporary blank image
    img_path = tmp_path / "test.img"
    # Use the class method to create a default image
    FAT12Image.create_empty_image(str(img_path))
    
    # Load it and verify the OEM Name from the snippet
    handler = FAT12Image(str(img_path))
    assert "YAMAHA" in handler.oem_name
    assert handler.bytes_per_cluster == 512
    assert handler.sectors_per_cluster == 1
    assert handler.reserved_sectors == 1
    assert handler.num_fats == 2
    assert handler.root_entries == 224
    assert handler.total_sectors == 2880
    assert handler.media_descriptor == 0xF0
    assert handler.sectors_per_fat == 9
    assert handler.sectors_per_track == 18
    
    # Verify the FAT type is FAT12
    assert handler.fat_type == "FAT12"
    
    # Verify the FAT is initialized to 0xFF
    fat_data = handler.read_fat()
    assert fat_data[0] == 0xF0
    assert fat_data[1] == 0xFF
    assert fat_data[2] == 0xFF