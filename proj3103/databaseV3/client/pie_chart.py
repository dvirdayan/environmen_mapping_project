import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Frame
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
import time

matplotlib.use("TkAgg")  # Set the backend before importing pyplot


class ProtocolPieChart(Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Create matplotlib figure and canvas
        self.figure = plt.Figure(figsize=(5, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Initial data
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'HTTP': 0,
            'HTTPS': 0,
            'FTP': 0,
            'SMTP': 0,
            'Other': 0
        }

        # Colors for the pie chart
        self.colors = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d', '#ffc658']

        # **FIXED: Add throttling for pie chart updates**
        self.last_update = 0
        self.update_lock = False

        # Initial plot
        self.update_plot()

    def update_plot(self, protocol_counts=None):
        """Update the pie chart with new protocol counts"""
        # **FIXED: Add throttling to prevent excessive updates**
        current_time = time.time()

        # Throttle updates to once per 2 seconds for pie chart
        if current_time - self.last_update < 2.0:
            return

        # Prevent overlapping updates
        if self.update_lock:
            return

        self.update_lock = True
        self.last_update = current_time

        try:
            if protocol_counts:
                self.protocol_counts = protocol_counts

            # Clear previous plot
            self.ax.clear()

            # Filter out zero values for better visualization
            filtered_data = {k: v for k, v in self.protocol_counts.items() if v > 0}

            if sum(filtered_data.values()) > 0:  # Only plot if we have data
                labels = filtered_data.keys()
                sizes = filtered_data.values()

                # Create pie chart
                wedges, texts, autotexts = self.ax.pie(
                    sizes,
                    labels=labels,
                    autopct='%1.1f%%',
                    startangle=90,
                    colors=self.colors[:len(filtered_data)]
                )

                # Equal aspect ratio ensures that pie is drawn as a circle
                self.ax.axis('equal')

                # Set title
                self.ax.set_title('Protocol Distribution')

                # Make text more readable
                for text in texts:
                    text.set_fontsize(9)
                for autotext in autotexts:
                    autotext.set_fontsize(9)
                    autotext.set_color('white')

            else:
                # No data case
                self.ax.text(0.5, 0.5, 'No packets captured yet',
                             horizontalalignment='center',
                             verticalalignment='center',
                             transform=self.ax.transAxes)
                self.ax.axis('off')

            # Redraw canvas
            self.canvas.draw()

        except Exception as e:
            print(f"Error updating pie chart: {e}")
        finally:
            self.update_lock = False


# Function to integrate the ProtocolPieChart into the existing PacketCaptureClientUI
def integrate_pie_chart_to_ui(ui_class):
    # Store original setup_ui method
    original_setup_ui = ui_class.setup_ui

    # Create enhanced setup_ui method
    def enhanced_setup_ui(self):
        # Call original method first
        original_setup_ui(self)

        # Find the stats_frame or create a new one for the pie chart
        main_frame = [child for child in self.root.winfo_children()
                      if isinstance(child, ttk.Frame)][0]

        # Create a notebook tab for the pie chart
        notebook = None
        for child in main_frame.winfo_children():
            if isinstance(child, ttk.Notebook):
                notebook = child
                break

        if notebook:
            # Create a frame for the pie chart
            pie_chart_frame = ttk.Frame(notebook, padding="10")
            notebook.add(pie_chart_frame, text="Protocol Chart")

            # Add the pie chart to the frame
            self.protocol_pie_chart = ProtocolPieChart(pie_chart_frame)
            self.protocol_pie_chart.pack(fill=tk.BOTH, expand=True)

    # Override the original update_protocol_counts method
    original_update_protocol_counts = ui_class.update_protocol_counts

    def enhanced_update_protocol_counts(self, protocol_counts):
        # Call original method
        original_update_protocol_counts(self, protocol_counts)

        # **FIXED: Only update pie chart with throttling and lock check**
        if hasattr(self, 'protocol_pie_chart'):
            # Check if the pie chart is not currently updating to prevent conflicts
            if not hasattr(self, 'pie_chart_update_lock') or not self.pie_chart_update_lock:
                self.protocol_pie_chart.update_plot(protocol_counts)

    # **FIXED: Override the environment-specific update method as well**
    def enhanced_update_protocol_counts_for_env(self, protocol_counts, environment=None):
        # Only update main UI and pie chart with global stats
        if environment is None:
            # This is global stats - update the main UI and pie chart
            enhanced_update_protocol_counts(self, protocol_counts)
        else:
            # This is environment-specific stats - don't update main UI to prevent flashing
            pass

    # Replace methods in the class
    ui_class.setup_ui = enhanced_setup_ui
    ui_class.update_protocol_counts = enhanced_update_protocol_counts

    # Add the environment method if it doesn't exist
    if hasattr(ui_class, 'update_protocol_counts_for_env'):
        ui_class.update_protocol_counts_for_env = enhanced_update_protocol_counts_for_env

    return ui_class
