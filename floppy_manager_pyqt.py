#!/usr/bin/env python3

# Copyright (c) 2026 Stephen P Smith
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
FAT12 Floppy Disk Image Manager
A modern GUI tool for managing files on FAT12 floppy disk images with VFAT LFN support
"""

import sys
import os
import shutil
from pathlib import Path
from typing import List, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QFileDialog,
    QMessageBox, QLabel, QStatusBar, QMenuBar, QMenu, QHeaderView,
    QDialog, QTabWidget
)
from PyQt6.QtCore import Qt, QSettings
from PyQt6.QtGui import QIcon, QAction, QKeySequence

# Import the FAT12 handler
from fat12_handler import FAT12Image


class BootSectorViewer(QDialog):
    """Dialog to view boot sector and EBPB information"""
    
    def __init__(self, image: FAT12Image, parent=None):
        super().__init__(parent)
        self.image = image
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the viewer UI"""
        self.setWindowTitle("Boot Sector & EBPB Information")
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
        
        # EBPB Table
        ebpb_table = QTableWidget()
        ebpb_table.setColumnCount(2)
        ebpb_table.setHorizontalHeaderLabels(['Field', 'Value'])
        ebpb_table.horizontalHeader().setStretchLastSection(True)
        ebpb_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ebpb_table.setAlternatingRowColors(True)
        
        boot_sig_status = "Valid (0x29)" if self.image.boot_signature == 0x29 else f"Invalid/Old (0x{self.image.boot_signature:02X})"
        
        # EBPB data
        ebpb_data = [
            ('Drive Number', f'{self.image.drive_number} (0x{self.image.drive_number:02X})'),
            ('Reserved/Current Head', str(self.image.reserved_ebpb)),
            ('Boot Signature', boot_sig_status),
            ('Volume ID (Serial Number)', f'0x{self.image.volume_id:08X}'),
            ('Volume Label', self.image.volume_label if self.image.volume_label else '(none)'),
            ('File System Type (from EBPB)', self.image.fs_type_from_EBPB if self.image.fs_type_from_EBPB else '(none)'),
        ]
        
        ebpb_table.setRowCount(len(ebpb_data))
        for i, (field, value) in enumerate(ebpb_data):
            ebpb_table.setItem(i, 0, QTableWidgetItem(field))
            ebpb_table.setItem(i, 1, QTableWidgetItem(value))
        
        ebpb_table.resizeColumnsToContents()
        tabs.addTab(ebpb_table, "Extended BIOS Parameter Block")
        
        # Calculated Info Table
        calc_table = QTableWidget()
        calc_table.setColumnCount(2)
        calc_table.setHorizontalHeaderLabels(['Field', 'Value'])
        calc_table.horizontalHeader().setStretchLastSection(True)
        calc_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        calc_table.setAlternatingRowColors(True)
        
        total_bytes = self.image.total_sectors * self.image.bytes_per_sector
        
        calc_data = [
            ('Detected File System Type', self.image.fat_type),
            ('FAT Start Offset', f'{self.image.fat_start:,} bytes'),
            ('Root Directory Start', f'{self.image.root_start:,} bytes'),
            ('Root Directory Size', f'{self.image.root_size:,} bytes'),
            ('Data Area Start', f'{self.image.data_start:,} bytes'),
            ('Bytes per Cluster', str(self.image.bytes_per_cluster)),
            ('Total Data Sectors', str(self.image.total_data_sectors)),
            ('Total Capacity', f'{total_bytes:,} bytes ({total_bytes / 1024 / 1024:.2f} MB)'),
        ]
        
        calc_table.setRowCount(len(calc_data))
        for i, (field, value) in enumerate(calc_data):
            calc_table.setItem(i, 0, QTableWidgetItem(field))
            calc_table.setItem(i, 1, QTableWidgetItem(value))
        
        calc_table.resizeColumnsToContents()
        tabs.addTab(calc_table, "Calculated Information")
        
        layout.addWidget(tabs)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class RootDirectoryViewer(QDialog):
    """Dialog to view complete root directory information"""
    
    def __init__(self, image: FAT12Image, parent=None):
        super().__init__(parent)
        self.image = image
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the viewer UI"""
        self.setWindowTitle("Root Directory Information")
        self.setGeometry(100, 100, 1200, 600)
        
        layout = QVBoxLayout(self)
        
        # Info label
        entries = self.image.read_root_directory()
        info_label = QLabel(f"Total entries: {len(entries)} of {self.image.root_entries} available")
        info_label.setStyleSheet("QLabel { font-weight: bold; padding: 5px; }")
        layout.addWidget(info_label)
        
        # Table
        table = QTableWidget()
        table.setColumnCount(14)
        table.setHorizontalHeaderLabels([
            'Filename (Long)', 
            'Filename (8.3)',
            'Size (bytes)', 
            'First Cluster',
            'Attributes',
            'Created Date/Time',
            'Last Accessed',
            'Last Modified',
            'Read-Only',
            'Hidden',
            'System',
            'Directory',
            'Archive',
            'Index'
        ])
        
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        
        # Populate table
        table.setRowCount(len(entries))
        for i, entry in enumerate(entries):
            # Long filename
            table.setItem(i, 0, QTableWidgetItem(entry['name']))
            
            # Short filename (8.3)
            table.setItem(i, 1, QTableWidgetItem(entry['short_name']))
            
            # Size
            size_item = QTableWidgetItem(f"{entry['size']:,}")
            size_item.setData(Qt.ItemDataRole.UserRole, entry['size'])  # For sorting
            table.setItem(i, 2, size_item)
            
            # First Cluster
            table.setItem(i, 3, QTableWidgetItem(str(entry['cluster'])))
            
            # Attributes (hex)
            table.setItem(i, 4, QTableWidgetItem(f"0x{entry['attributes']:02X}"))
            
            # Creation date/time
            table.setItem(i, 5, QTableWidgetItem(entry['creation_datetime_str']))
            
            # Last accessed
            table.setItem(i, 6, QTableWidgetItem(entry['last_accessed_str']))
            
            # Last modified
            table.setItem(i, 7, QTableWidgetItem(entry['last_modified_datetime_str']))
            
            # Attribute flags
            table.setItem(i, 8, QTableWidgetItem('Yes' if entry['is_read_only'] else 'No'))
            table.setItem(i, 9, QTableWidgetItem('Yes' if entry['is_hidden'] else 'No'))
            table.setItem(i, 10, QTableWidgetItem('Yes' if entry['is_system'] else 'No'))
            table.setItem(i, 11, QTableWidgetItem('Yes' if entry['is_dir'] else 'No'))
            table.setItem(i, 12, QTableWidgetItem('Yes' if entry['is_archive'] else 'No'))
            
            # Index
            table.setItem(i, 13, QTableWidgetItem(str(entry['index'])))
        
        # Resize columns
        header = table.horizontalHeader()
        for col in range(table.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(table)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)


class FloppyManagerWindow(QMainWindow):
    """Main window for the floppy manager"""

    def __init__(self, image_path: Optional[str] = None):
        super().__init__()

        # Settings
        self.settings = QSettings('FAT12FloppyManager', 'Settings')
        self.confirm_delete = self.settings.value('confirm_delete', True, type=bool)
        self.confirm_replace = self.settings.value('confirm_replace', True, type=bool)
        self.use_numeric_tail = self.settings.value('use_numeric_tail', False, type=bool)

        # Restore window geometry if available
        geometry = self.settings.value('window_geometry')
        if geometry:
            self.restoreGeometry(geometry)

        self.image_path = image_path
        self.image = None

        self.setup_ui()

        # Load image if provided or restore last image
        if image_path:
            self.load_image(image_path)
        else:
            # Try to restore last opened image
            last_image = self.settings.value('last_image_path', '')
            if last_image and Path(last_image).exists():
                self.load_image(last_image)
            else:
                # No image loaded, show empty state
                self.status_bar.showMessage("No image loaded. Create new or open existing image.")

    def setup_ui(self):
        """Create the user interface"""
        self.setWindowTitle("FAT12 Floppy Manager")
        self.setGeometry(100, 100, 1000, 600)

        # Enable drag and drop
        self.setAcceptDrops(True)

        # Set window icon if available
        icon_path = Path(__file__).parent / 'floppy_icon.ico'
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # Create menu bar
        self.create_menus()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        layout = QVBoxLayout(central_widget)

        # Top toolbar
        toolbar = QHBoxLayout()

        # Buttons
        self.add_btn = QPushButton("📁 Add Files")
        self.add_btn.setToolTip("Add files to the floppy image")
        self.add_btn.clicked.connect(self.add_files)

        self.extract_btn = QPushButton("💾 Extract Selected")
        self.extract_btn.setToolTip("Extract selected files to your computer")
        self.extract_btn.clicked.connect(self.extract_selected)

        self.delete_btn = QPushButton("🗑️ Delete Selected")
        self.delete_btn.setToolTip("Delete selected files (or press Delete key)")
        self.delete_btn.clicked.connect(self.delete_selected)

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setToolTip("Reload the file list")
        self.refresh_btn.clicked.connect(self.refresh_file_list)

        toolbar.addWidget(self.add_btn)
        toolbar.addWidget(self.extract_btn)
        toolbar.addWidget(self.delete_btn)
        toolbar.addWidget(self.refresh_btn)
        toolbar.addStretch()

        # Info label
        self.info_label = QLabel()
        self.info_label.setStyleSheet("QLabel { color: #555; font-weight: bold; }")
        toolbar.addWidget(self.info_label)

        layout.addLayout(toolbar)

        # File table - now with 5 columns
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['Filename', 'Short Name (8.3)', 'Size', 'Type', 'Index'])

        # Hide the index column (used internally)
        self.table.setColumnHidden(4, True)

        # Configure table
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # Set column widths
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Filename
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Short name
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Size
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Type

        # Double-click to extract
        self.table.doubleClicked.connect(self.extract_selected)

        layout.addWidget(self.table)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready | Tip: Drag and drop files to add them to the floppy")

        # Keyboard shortcuts
        self.table.keyPressEvent = self.table_key_press

    def create_menus(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        new_action = QAction("&New Image...", self)
        new_action.setShortcut(QKeySequence.StandardKey.New)
        new_action.setToolTip("Create a new blank floppy disk image")
        new_action.triggered.connect(self.create_new_image)
        file_menu.addAction(new_action)

        open_action = QAction("&Open Image...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_image)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        save_as_action = QAction("Save Image &As...", self)
        save_as_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        save_as_action.setToolTip("Save a copy of the current image")
        save_as_action.triggered.connect(self.save_image_as)
        file_menu.addAction(save_as_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        boot_sector_action = QAction("&Boot Sector && EBPB Information...", self)
        boot_sector_action.setToolTip("View complete boot sector and EBPB details")
        boot_sector_action.triggered.connect(self.show_boot_sector_info)
        view_menu.addAction(boot_sector_action)

        root_dir_action = QAction("&Root Directory Information...", self)
        root_dir_action.setToolTip("View complete root directory details")
        root_dir_action.triggered.connect(self.show_root_directory_info)
        view_menu.addAction(root_dir_action)

        # Settings menu
        settings_menu = menubar.addMenu("&Settings")

        self.confirm_delete_action = QAction("Confirm before deleting", self)
        self.confirm_delete_action.setCheckable(True)
        self.confirm_delete_action.setChecked(self.confirm_delete)
        self.confirm_delete_action.triggered.connect(self.toggle_confirm_delete)
        settings_menu.addAction(self.confirm_delete_action)

        self.confirm_replace_action = QAction("Confirm before replacing files", self)
        self.confirm_replace_action.setCheckable(True)
        self.confirm_replace_action.setChecked(self.confirm_replace)
        self.confirm_replace_action.triggered.connect(self.toggle_confirm_replace)
        settings_menu.addAction(self.confirm_replace_action)

        settings_menu.addSeparator()

        self.use_numeric_tail_action = QAction("Use numeric tails for 8.3 names (~1, ~2, etc.)", self)
        self.use_numeric_tail_action.setCheckable(True)
        self.use_numeric_tail_action.setChecked(self.use_numeric_tail)
        self.use_numeric_tail_action.setToolTip("When enabled, uses Windows-style numeric tails (e.g., LONGFI~1.TXT). When disabled, simply truncates names (like Linux nonumtail option).")
        self.use_numeric_tail_action.triggered.connect(self.toggle_numeric_tail)
        settings_menu.addAction(self.use_numeric_tail_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def toggle_confirm_delete(self):
        """Toggle delete confirmation"""
        self.confirm_delete = self.confirm_delete_action.isChecked()
        self.settings.setValue('confirm_delete', self.confirm_delete)

    def toggle_confirm_replace(self):
        """Toggle replace confirmation"""
        self.confirm_replace = self.confirm_replace_action.isChecked()
        self.settings.setValue('confirm_replace', self.confirm_replace)

    def toggle_numeric_tail(self):
        """Toggle numeric tail usage for 8.3 name generation"""
        self.use_numeric_tail = self.use_numeric_tail_action.isChecked()
        self.settings.setValue('use_numeric_tail', self.use_numeric_tail)
        
        # Show info message
        if self.use_numeric_tail:
            mode_desc = "Windows-style numeric tails enabled (e.g., LONGFI~1.TXT)"
        else:
            mode_desc = "Simple truncation mode enabled (like Linux nonumtail)"
        
        self.status_bar.showMessage(f"8.3 name generation: {mode_desc}")

    def table_key_press(self, event):
        """Handle keyboard events in the table"""
        if event.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace):
            self.delete_selected()
        else:
            # Call the original keyPressEvent
            QTableWidget.keyPressEvent(self.table, event)

    def load_image(self, filepath: str):
        """Load a floppy disk image"""
        try:
            self.image = FAT12Image(filepath)
            self.image_path = filepath
            self.setWindowTitle(f"FAT12 Floppy Manager - {Path(filepath).name}")

            # Save as last opened image
            self.settings.setValue('last_image_path', filepath)

            self.refresh_file_list()
            self.status_bar.showMessage(f"Loaded: {Path(filepath).name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load image: {e}")
            self.image = None
            self.image_path = None
            self.setWindowTitle("FAT12 Floppy Manager")

    def refresh_file_list(self):
        """Refresh the file list from the image"""
        self.table.setRowCount(0)

        if not self.image:
            self.info_label.setText("No image loaded")
            return

        try:
            entries = self.image.read_root_directory()

            for entry in entries:
                if not entry['is_dir']:
                    row = self.table.rowCount()
                    self.table.insertRow(row)

                    # Filename (long name)
                    self.table.setItem(row, 0, QTableWidgetItem(entry['name']))

                    # Short name (8.3)
                    self.table.setItem(row, 1, QTableWidgetItem(entry['short_name']))

                    # Size
                    size_str = f"{entry['size']:,} bytes"
                    self.table.setItem(row, 2, QTableWidgetItem(size_str))

                    # Type
                    file_type = Path(entry['name']).suffix.upper().lstrip('.')
                    self.table.setItem(row, 3, QTableWidgetItem(file_type))

                    # Index (hidden)
                    self.table.setItem(row, 4, QTableWidgetItem(str(entry['index'])))

            # Update info
            free_clusters = len(self.image.find_free_clusters())
            free_space = free_clusters * self.image.bytes_per_cluster
            self.info_label.setText(f"{len(entries)} files | {free_space:,} bytes free")
            self.status_bar.showMessage(f"Loaded {len(entries)} files")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read directory: {e}")

    def show_boot_sector_info(self):
        """Show boot sector and EBPB information"""
        if not self.image:
            QMessageBox.information(
                self, 
                "No Image Loaded", 
                "Please load or create a floppy image first."
            )
            return
        
        viewer = BootSectorViewer(self.image, self)
        viewer.exec()

    def show_root_directory_info(self):
        """Show complete root directory information"""
        if not self.image:
            QMessageBox.information(
                self, 
                "No Image Loaded", 
                "Please load or create a floppy image first."
            )
            return
        
        viewer = RootDirectoryViewer(self.image, self)
        viewer.exec()

    def add_files(self):
        """Add files to the image via file dialog"""
        if not self.image:
            QMessageBox.information(
                self,
                "No Image Loaded",
                "Please create a new image or open an existing one first."
            )
            return

        filenames, _ = QFileDialog.getOpenFileNames(
            self,
            "Select files to add",
            "",
            "All files (*.*)"
        )

        if not filenames:
            return

        self.add_files_from_list(filenames)

    def add_files_from_list(self, filenames: list):
        """Add files from a list of file paths (used by both dialog and drag-drop)"""
        if not self.image:
            return

        success_count = 0
        fail_count = 0

        for filepath in filenames:
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()

                path_obj = Path(filepath)
                original_name = path_obj.name

                # Get existing 8.3 names
                existing_83_names = self.image.get_existing_83_names()
                
                # Generate the 8.3 name that will be used
                short_name_83 = FAT12Image.generate_83_name(
                    original_name, 
                    existing_83_names, 
                    self.use_numeric_tail
                )
                
                # Format 8.3 name for display (add dot back)
                short_display = short_name_83[:8].strip() + '.' + short_name_83[8:11].strip()
                short_display = short_display.rstrip('.')

                # Check if file already exists
                existing_entries = self.image.read_root_directory()
                collision_entry = None
                
                # Check both long name and short name
                for e in existing_entries:
                    e_short_83 = e['short_name'].replace('.', '').ljust(11).upper()
                    if e_short_83 == short_name_83:
                        collision_entry = e
                        break

                if collision_entry:
                    if self.confirm_replace:
                        msg = f"The file '{original_name}' will be saved with 8.3 name '{short_display}', which already exists"
                        if collision_entry['name'] != collision_entry['short_name']:
                            msg += f" (long name: '{collision_entry['name']}')"
                        msg += ".\n\nDo you want to replace it?"
                        
                        response = QMessageBox.question(
                            self,
                            "File Exists",
                            msg,
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                        )
                        if response == QMessageBox.StandardButton.No:
                            continue

                    # Delete the existing file
                    self.image.delete_file(collision_entry)

                # Write the new file
                if self.image.write_file_to_image(original_name, data, self.use_numeric_tail):
                    success_count += 1
                else:
                    fail_count += 1
                    QMessageBox.warning(
                        self,
                        "Error",
                        f"Failed to write {original_name} - disk may be full"
                    )

            except Exception as e:
                fail_count += 1
                QMessageBox.critical(self, "Error", f"Failed to add {Path(filepath).name}: {e}")

        self.refresh_file_list()

        if success_count > 0:
            self.status_bar.showMessage(f"Added {success_count} file(s)")
        if fail_count > 0:
            QMessageBox.warning(self, "Warning", f"Failed to add {fail_count} file(s)")

    def extract_selected(self):
        """Extract selected files"""
        if not self.image:
            QMessageBox.information(self, "No Image Loaded", "No image loaded.")
            return

        selected_rows = set(item.row() for item in self.table.selectedItems())

        if not selected_rows:
            QMessageBox.information(self, "Info", "Please select files to extract")
            return

        save_dir = QFileDialog.getExistingDirectory(self, "Select folder to save files")
        if not save_dir:
            return

        entries = self.image.read_root_directory()
        success_count = 0

        for row in selected_rows:
            entry_index = int(self.table.item(row, 4).text())
            entry = next((e for e in entries if e['index'] == entry_index), None)

            if entry:
                try:
                    data = self.image.extract_file(entry)
                    # Use the long filename (original name) when extracting
                    output_path = os.path.join(save_dir, entry['name'])

                    with open(output_path, 'wb') as f:
                        f.write(data)

                    success_count += 1
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to extract {entry['name']}: {e}")

        if success_count > 0:
            self.status_bar.showMessage(f"Extracted {success_count} file(s) to {save_dir}")
            QMessageBox.information(self, "Success", f"Extracted {success_count} file(s)")

    def delete_selected(self):
        """Delete selected files"""
        if not self.image:
            QMessageBox.information(self, "No Image Loaded", "No image loaded.")
            return

        selected_rows = set(item.row() for item in self.table.selectedItems())

        if not selected_rows:
            QMessageBox.information(self, "Info", "Please select files to delete")
            return

        if self.confirm_delete:
            response = QMessageBox.question(
                self,
                "Confirm Delete",
                f"Delete {len(selected_rows)} file(s) from the disk image?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if response == QMessageBox.StandardButton.No:
                return

        entries = self.image.read_root_directory()
        success_count = 0

        for row in selected_rows:
            entry_index = int(self.table.item(row, 4).text())
            entry = next((e for e in entries if e['index'] == entry_index), None)

            if entry:
                if self.image.delete_file(entry):
                    success_count += 1
                else:
                    QMessageBox.critical(self, "Error", f"Failed to delete {entry['name']}")

        self.refresh_file_list()

        if success_count > 0:
            self.status_bar.showMessage(f"Deleted {success_count} file(s)")

    def create_new_image(self):
        """Create a new blank floppy disk image"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Create New Floppy Image",
            "",
            "Floppy images (*.img);;All files (*.*)"
        )

        if not filename:
            return

        # Ensure .img extension
        if not filename.lower().endswith('.img'):
            filename += '.img'

        try:
            # Create a blank 1.44MB floppy image using the handler
            FAT12Image.create_blank_image(filename)

            # Load the new image
            self.load_image(filename)

            QMessageBox.information(
                self,
                "Success",
                f"Created new floppy image:\n{Path(filename).name}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create image: {e}")

    def save_image_as(self):
        """Save a copy of the current floppy image"""
        if not self.image:
            QMessageBox.information(self, "Info", "No image loaded to save")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Image As",
            Path(self.image_path).name if self.image_path else "floppy.img",
            "Floppy images (*.img);;All files (*.*)"
        )

        if not filename:
            return

        # Ensure .img extension
        if not filename.lower().endswith('.img'):
            filename += '.img'

        try:
            # Copy the current image file
            shutil.copy2(self.image_path, filename)

            QMessageBox.information(
                self,
                "Success",
                f"Image saved as:\n{Path(filename).name}"
            )

            self.status_bar.showMessage(f"Saved as: {Path(filename).name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save image: {e}")

    def open_image(self):
        """Open a different floppy image"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select FAT12 Floppy Image",
            "",
            "Floppy images (*.img *.ima);;All files (*.*)"
        )

        if filename:
            self.load_image(filename)

    def show_about(self):
        """Show about dialog"""
        about_text = """<h2>FAT12 Floppy Manager</h2>
        <p><b>Version 2.0</b></p>

        <p>A modern tool for managing files on FAT12 floppy disk images with VFAT long filename support.</p>

        <p><b>Features:</b></p>
        <ul>
        <li>FAT12 filesystem support with VFAT long filenames</li>
        <li>Windows-compatible 8.3 name generation with numeric tails</li>
        <li>Toggleable numeric tail mode (Windows-style vs. simple truncation)</li>
        <li>Create new blank floppy images</li>
        <li>Writes directly to the image file without needing to mount it as a drive</li>
        <li>Displays both long filenames and 8.3 short names</li>
        <li>Save copies of floppy images</li>
        <li>Drag and drop files to add them</li>
        <li>Delete files (press Del key)</li>
        <li>Extract files with original long names</li>
        <li>View boot sector and EBPB information</li>
        <li>View complete root directory information with timestamps</li>
        <li>Remembers last opened image and settings</li>
        </ul>

        <p><b>Keyboard Shortcuts:</b></p>
        <ul>
        <li>Ctrl+N - Create new image</li>
        <li>Ctrl+O - Open image</li>
        <li>Ctrl+Shift+S - Save image as</li>
        <li>Del/Backspace - Delete selected files</li>
        <li>Double-click - Extract file</li>
        </ul>

        <p><small>© 2026 Stephen P Smith | MIT License</small></p>
        """
        QMessageBox.about(self, "About", about_text)

    def closeEvent(self, event):
        """Handle window close event - save state"""
        # Save window geometry
        self.settings.setValue('window_geometry', self.saveGeometry())
        event.accept()

    def dragEnterEvent(self, event):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        """Handle drop event - add files to floppy"""
        if not self.image:
            QMessageBox.information(
                self,
                "No Image Loaded",
                "Please create a new image or open an existing one first."
            )
            event.ignore()
            return

        # Get dropped files
        files = []
        for url in event.mimeData().urls():
            filepath = url.toLocalFile()
            if filepath and Path(filepath).is_file():
                files.append(filepath)

        if not files:
            event.ignore()
            return

        event.acceptProposedAction()

        # Add files using existing method
        self.add_files_from_list(files)


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("FAT12 Floppy Manager")
    app.setOrganizationName("FAT12FloppyManager")

    # Set application style
    app.setStyle('Fusion')

    # Create main window
    window = FloppyManagerWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
