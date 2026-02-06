from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, 
    QTabWidget, QHeaderView, QPushButton, QLabel
)
from PyQt6.QtCore import Qt
import struct

# Import the FAT12 handler
from fat12_handler import FAT12Image

class BootSectorViewer(QDialog):
    """Dialog to view boot sector information"""
    
    def __init__(self, image: FAT12Image, parent=None):
        super().__init__(parent)
        self.image = image
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the viewer UI"""
        self.setWindowTitle("Boot Sector Information")
        self.setGeometry(100, 100, 800, 600)
        
        layout = QVBoxLayout(self)
        
        # Create tab widget for different sections
        tabs = QTabWidget()
        
        # Boot Sector / BPB Table
        bpb_table = QTableWidget()
        bpb_table.setColumnCount(2)
        bpb_table.setHorizontalHeaderLabels(['Field', 'Value'])
        bpb_table.horizontalHeader().setStretchLastSection(True)
        bpb_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        bpb_table.setAlternatingRowColors(True)
        
        # BPB data
        bpb_data = [
            ('OEM Name', self.image.oem_name),
            ('Bytes per Sector', str(self.image.bytes_per_sector)),
            ('Sectors per Cluster', str(self.image.sectors_per_cluster)),
            ('Reserved Sectors', str(self.image.reserved_sectors)),
            ('Number of FATs', str(self.image.num_fats)),
            ('Root Directory Entries', str(self.image.root_entries)),
            ('Total Sectors', str(self.image.total_sectors)),
            ('Media Descriptor', f'0x{self.image.media_descriptor:02X}'),
            ('Sectors per FAT', str(self.image.sectors_per_fat)),
            ('Sectors per Track', str(self.image.sectors_per_track)),
            ('Number of Heads', str(self.image.number_of_heads)),
            ('Hidden Sectors', str(self.image.hidden_sectors)),
        ]
        
        bpb_table.setRowCount(len(bpb_data))
        for i, (field, value) in enumerate(bpb_data):
            bpb_table.setItem(i, 0, QTableWidgetItem(field))
            bpb_table.setItem(i, 1, QTableWidgetItem(value))
        
        bpb_table.resizeColumnsToContents()
        tabs.addTab(bpb_table, "BIOS Parameter Block")
                
        # Calculated Info Table
        vol_geom_table = QTableWidget()
        vol_geom_table.setColumnCount(2)
        vol_geom_table.setHorizontalHeaderLabels(['Field', 'Value'])
        vol_geom_table.horizontalHeader().setStretchLastSection(True)
        vol_geom_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vol_geom_table.setAlternatingRowColors(True)
        
        total_bytes = self.image.total_sectors * self.image.bytes_per_sector
        
        vol_geom_data = [
            ('Detected File System Type', self.image.fat_type),
            ('FAT Start Offset', f'{self.image.fat_start:,} bytes'),
            ('Root Directory Start', f'{self.image.root_start:,} bytes'),
            ('Root Directory Size', f'{self.image.root_size:,} bytes'),
            ('Data Area Start', f'{self.image.data_start:,} bytes'),
            ('Bytes per Cluster', str(self.image.bytes_per_cluster)),
            ('Total Data Sectors', str(self.image.total_data_sectors)),
            ('Total Capacity', f'{total_bytes:,} bytes ({total_bytes / 1024 / 1024:.2f} MB)'),
        ]
        
        vol_geom_table.setRowCount(len(vol_geom_data))
        for i, (field, value) in enumerate(vol_geom_data):
            vol_geom_table.setItem(i, 0, QTableWidgetItem(field))
            vol_geom_table.setItem(i, 1, QTableWidgetItem(value))
        
        vol_geom_table.resizeColumnsToContents()
        tabs.addTab(vol_geom_table, "Volume Geometry")
        
        layout.addWidget(tabs)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class RootDirectoryViewer(QDialog):
    """Dialog to view complete root directory information with detailed VFAT tooltips"""
    
    def __init__(self, image: FAT12Image, parent=None):
        super().__init__(parent)
        self.image = image
        self.raw_entries = []  # Store raw directory entry data
        self.setup_ui()
    
    def format_raw_entry_tooltip(self, index: int) -> str:
        """Format a detailed tooltip showing the raw directory entry structure
        
        This shows the complete 32-byte layout of the directory entry including
        all LFN entries that precede the short entry.
        """
        # Find all entries related to this file (LFN + short entry)
        related_entries = []
        
        # Sanity check - make sure index is within bounds
        if index >= len(self.raw_entries):
            return "<html><body>Invalid entry index</body></html>"
        
        # Get the short entry first
        short_entry_data = self.raw_entries[index][1]
        related_entries.append((index, short_entry_data))
        
        # Walk backwards to find LFN entries
        i = index - 1
        while i >= 0:
            entry_data = self.raw_entries[i][1]
            attr = entry_data[11]
            
            # Check if LFN entry
            if attr == 0x0F:
                related_entries.insert(0, (i, entry_data))
                i -= 1
            else:
                # Not an LFN entry, stop searching
                break
        
        # Build HTML tooltip with transposed (horizontal) tables
        html = "<html><head><style>"
        html += "table { border-collapse: collapse; font-family: monospace; font-size: 11px; margin-bottom: 8px; }"
        html += "th, td { border: 1px solid #666; padding: 3px 6px; text-align: left; }"
        html += "th { background-color: #444; color: white; font-weight: bold; }"
        html += ".lfn { background-color: #e8f4f8; }"
        html += ".short { background-color: #f8f4e8; }"
        html += "</style></head><body>"
        
        for entry_idx, entry_data in related_entries:
            attr = entry_data[11]
            
            if attr == 0x0F:  # LFN Entry
                seq = entry_data[0]
                is_last = (seq & 0x40) != 0
                seq_num = seq & 0x1F
                checksum = entry_data[13]
                lfn_type = entry_data[12]
                first_cluster = struct.unpack('<H', entry_data[26:28])[0]
                
                # Extract character portions
                chars1 = entry_data[1:11]   # 5 chars (10 bytes)
                chars2 = entry_data[14:26]  # 6 chars (12 bytes)
                chars3 = entry_data[28:32]  # 2 chars (4 bytes)
                
                # Try to decode
                try:
                    text1 = chars1.decode('utf-16le').replace('\x00', '∅').replace('\uffff', '█')
                    text2 = chars2.decode('utf-16le').replace('\x00', '∅').replace('\uffff', '█')
                    text3 = chars3.decode('utf-16le').replace('\x00', '∅').replace('\uffff', '█')
                except:
                    text1 = '???'
                    text2 = '???'
                    text3 = '???'
                
                # Format hex for all characters (show more bytes)
                hex1 = ' '.join(f'{b:02X}' for b in chars1)
                hex2 = ' '.join(f'{b:02X}' for b in chars2)
                hex3 = ' '.join(f'{b:02X}' for b in chars3)
                
                html += f"<b style='background-color: #2c5aa0; color: white; padding: 3px 6px; display: block;'>"
                html += f"Entry #{entry_idx}: LFN (Seq {seq_num}{' LAST' if is_last else ''})</b>"
                html += "<table class='lfn'>"
                
                # Row 1: Field names
                html += "<tr><th>Sequence</th><th>Chars 1-5</th><th>Attr</th>"
                html += "<th>Type</th><th>Chksum</th><th>Chars 6-11</th><th>Cluster</th><th>Chars 12-13</th></tr>"
                
                # Row 2: Values
                html += f"<tr>"
                html += f"<td>0x{seq:02X}<br>({seq_num})</td>"
                html += f"<td>{hex1}<br>'{text1}'</td>"
                html += f"<td>0x{attr:02X}</td>"
                html += f"<td>0x{lfn_type:02X}</td>"
                html += f"<td>0x{checksum:02X}</td>"
                html += f"<td>{hex2}<br>'{text2}'</td>"
                html += f"<td>0x{first_cluster:04X}</td>"
                html += f"<td>{hex3}<br>'{text3}'</td></tr>"
                
                html += "</table>"
                
            else:  # Short Entry
                filename = entry_data[0:11].decode('ascii', errors='replace')
                attributes = entry_data[11]
                reserved = entry_data[12]
                creation_time_tenth = entry_data[13]
                creation_time = struct.unpack('<H', entry_data[14:16])[0]
                creation_date = struct.unpack('<H', entry_data[16:18])[0]
                last_access_date = struct.unpack('<H', entry_data[18:20])[0]
                first_cluster_high = struct.unpack('<H', entry_data[20:22])[0]
                last_modified_time = struct.unpack('<H', entry_data[22:24])[0]
                last_modified_date = struct.unpack('<H', entry_data[24:26])[0]
                first_cluster_low = struct.unpack('<H', entry_data[26:28])[0]
                file_size = struct.unpack('<I', entry_data[28:32])[0]
                
                # Decode attribute flags
                attr_flags = []
                if attributes & 0x01: attr_flags.append("RO")
                if attributes & 0x02: attr_flags.append("HID")
                if attributes & 0x04: attr_flags.append("SYS")
                if attributes & 0x08: attr_flags.append("VOL")
                if attributes & 0x10: attr_flags.append("DIR")
                if attributes & 0x20: attr_flags.append("ARC")
                attr_str = ",".join(attr_flags) if attr_flags else "-"
                
                html += f"<b style='background-color: #a07c2c; color: white; padding: 3px 6px; display: block;'>"
                html += f"Entry #{entry_idx}: Short Entry (8.3)</b>"
                html += "<table class='short'>"
                
                # Row 1: Field names
                html += "<tr><th>Filename</th><th>Attr</th><th>Res</th><th>Cr10ms</th>"
                html += "<th>CrTime</th><th>CrDate</th><th>AccDate</th><th>ClusHi</th>"
                html += "<th>ModTime</th><th>ModDate</th><th>ClusLo</th><th>Size</th></tr>"
                
                # Row 2: Values
                html += f"<tr>"
                html += f"<td>'{filename}'</td>"
                html += f"<td>0x{attributes:02X}<br>{attr_str}</td>"
                html += f"<td>0x{reserved:02X}</td>"
                html += f"<td>{creation_time_tenth}</td>"
                html += f"<td>{(creation_time>>11)&0x1F:02d}:{(creation_time>>5)&0x3F:02d}:{(creation_time&0x1F)*2:02d}</td>"
                html += f"<td>{((creation_date>>9)&0x7F)+1980}-{(creation_date>>5)&0x0F:02d}-{creation_date&0x1F:02d}</td>"
                html += f"<td>{((last_access_date>>9)&0x7F)+1980}-{(last_access_date>>5)&0x0F:02d}-{last_access_date&0x1F:02d}</td>"
                html += f"<td>0x{first_cluster_high:04X}</td>"
                html += f"<td>{(last_modified_time>>11)&0x1F:02d}:{(last_modified_time>>5)&0x3F:02d}:{(last_modified_time&0x1F)*2:02d}</td>"
                html += f"<td>{((last_modified_date>>9)&0x7F)+1980}-{(last_modified_date>>5)&0x0F:02d}-{last_modified_date&0x1F:02d}</td>"
                html += f"<td>{first_cluster_low}</td>"
                html += f"<td>{file_size:,}</td></tr>"
                
                html += "</table>"
        
        html += "</body></html>"
        return html
        
    def setup_ui(self):
        """Setup the viewer UI"""
        self.setWindowTitle("Root Directory Information")
        self.setGeometry(100, 100, 1200, 600)
        
        layout = QVBoxLayout(self)
        
        # Read raw entries
        self.raw_entries = self.image.read_raw_directory_entries()
        
        # Info label
        entries = self.image.read_root_directory()
        info_label = QLabel(
            f"Total entries: {len(entries)} of {self.image.root_entries} available | Each entry is 32 bytes | "
            f"Hover over any row to see detailed directory entry structure"
        )
        info_label.setStyleSheet("QLabel { font-weight: bold; padding: 5px; }")
        layout.addWidget(info_label)
        
        # Table
        table = QTableWidget()
        table.setColumnCount(12)
        table.setHorizontalHeaderLabels([
            'Index',
            'Filename (Long)', 
            'Filename (8.3)',
            'Size (bytes)',
            'Created Date/Time',
            'Last Accessed',
            'Last Modified',
            'Read-Only',
            'Hidden',
            'System',
            'Directory',
            'Archive'
        ])
        
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        
        # Populate table
        table.setRowCount(len(entries))
        for i, entry in enumerate(entries):

            # Index
            item = QTableWidgetItem(str(entry['index']))
            item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 0, item)

            # Long filename
            item = QTableWidgetItem(entry['name'])
            item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 1, item)
            
            # Short filename (8.3)
            item = QTableWidgetItem(entry['short_name'])
            item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 2, item)
            
            # Size
            size_item = QTableWidgetItem(f"{entry['size']:,}")
            size_item.setData(Qt.ItemDataRole.UserRole, entry['size'])  # For sorting
            size_item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 3, size_item)
            
            # Creation date/time
            item = QTableWidgetItem(entry['creation_datetime_str'])
            item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 4, item)
            
            # Last accessed
            item = QTableWidgetItem(entry['last_accessed_str'])
            item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 5, item)
            
            # Last modified
            item = QTableWidgetItem(entry['last_modified_datetime_str'])
            item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
            table.setItem(i, 6, item)
            
            # Attribute flags
            for col_offset, flag in enumerate([
                'is_read_only', 'is_hidden', 'is_system', 'is_dir', 'is_archive'
            ]):
                item = QTableWidgetItem('Yes' if entry[flag] else 'No')
                item.setToolTip(self.format_raw_entry_tooltip(entry['index']))
                table.setItem(i, 7 + col_offset, item)
            
        # Resize columns
        header = table.horizontalHeader()
        for col in range(table.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(table)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
