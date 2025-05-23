import tkinter as tk
from tkinter import ttk, Frame
import time

# Try to import matplotlib, with fallback if not available
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib

    matplotlib.use("TkAgg")
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Matplotlib not available - pie chart will use text display")


class ProtocolPieChart(Frame):
    def __init__(self, parent):
        super().__init__(parent)

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

        # Responsive throttling for pie chart updates
        self.last_update = 0
        self.update_interval = 2.0  # Update every 2 seconds (was 3)

        if MATPLOTLIB_AVAILABLE:
            self.setup_matplotlib_chart()
        else:
            self.setup_text_chart()

    def setup_matplotlib_chart(self):
        """Setup matplotlib pie chart"""
        try:
            # Create matplotlib figure and canvas
            self.figure = plt.Figure(figsize=(6, 4), dpi=100)
            self.ax = self.figure.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.figure, self)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Initial plot
            self.update_plot()

        except Exception as e:
            print(f"Error setting up matplotlib chart: {e}")
            self.setup_text_chart()

    def setup_text_chart(self):
        """Setup text-based chart as fallback"""
        # Create a text widget to display protocol stats
        self.text_widget = tk.Text(self, height=10, width=40)
        self.text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text_widget.yview)
        self.text_widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.update_text_display()

    def update_plot(self, protocol_counts=None):
        """Update the pie chart with new protocol counts"""
        current_time = time.time()
        if current_time - self.last_update < 1.0:
            return
        self.last_update = current_time
        try:
            if protocol_counts:
                self.protocol_counts = protocol_counts
            if MATPLOTLIB_AVAILABLE and hasattr(self, 'ax'):
                self.update_matplotlib_chart()
            else:
                self.update_text_display()
        except Exception as e:
            print(f"Error updating pie chart: {e}")

    def update_matplotlib_chart(self):
        """Update the matplotlib pie chart"""
        try:
            # Clear previous plot
            self.ax.clear()

            # Filter out zero values for better visualization
            filtered_data = {k: v for k, v in self.protocol_counts.items() if v > 0}

            if sum(filtered_data.values()) > 0:
                labels = list(filtered_data.keys())
                sizes = list(filtered_data.values())

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
                total_packets = sum(self.protocol_counts.values())
                self.ax.set_title(f'Protocol Distribution\n(Total Packets: {total_packets})')

                # Make text more readable
                for text in texts:
                    text.set_fontsize(10)
                for autotext in autotexts:
                    autotext.set_fontsize(9)
                    autotext.set_color('white')
                    autotext.set_weight('bold')

            else:
                # No data case
                self.ax.text(0.5, 0.5, 'No packets captured yet\nStart packet capture to see data',
                             horizontalalignment='center',
                             verticalalignment='center',
                             transform=self.ax.transAxes,
                             fontsize=12)
                self.ax.set_title('Protocol Distribution')
                self.ax.axis('off')

            # Redraw canvas
            if hasattr(self, 'canvas'):
                self.canvas.draw()

        except Exception as e:
            print(f"Error updating matplotlib chart: {e}")

    def update_text_display(self):
        """Update the text-based display"""
        try:
            if not hasattr(self, 'text_widget'):
                return

            # Clear the text widget
            self.text_widget.delete(1.0, tk.END)

            # Calculate total packets
            total_packets = sum(self.protocol_counts.values())

            # Add header
            self.text_widget.insert(tk.END, f"Protocol Distribution\n")
            self.text_widget.insert(tk.END, f"Total Packets: {total_packets}\n")
            self.text_widget.insert(tk.END, "-" * 30 + "\n\n")

            if total_packets > 0:
                # Sort protocols by count (descending)
                sorted_protocols = sorted(self.protocol_counts.items(),
                                          key=lambda x: x[1], reverse=True)

                for protocol, count in sorted_protocols:
                    if count > 0:
                        percentage = (count / total_packets) * 100
                        self.text_widget.insert(tk.END,
                                                f"{protocol:8}: {count:6} ({percentage:5.1f}%)\n")
            else:
                self.text_widget.insert(tk.END, "No packets captured yet.\n")
                self.text_widget.insert(tk.END, "Start packet capture to see data.\n")

            # Scroll to top
            self.text_widget.see(1.0)

        except Exception as e:
            print(f"Error updating text display: {e}")


def integrate_pie_chart_to_ui(ui_class):
    """Integrate the ProtocolPieChart into the existing PacketCaptureClientUI"""

    # Store original setup_ui method
    original_setup_ui = ui_class.setup_ui

    def enhanced_setup_ui(self):
        """Enhanced setup_ui method with pie chart integration"""
        # Call original method first
        original_setup_ui(self)

        try:
            # Find the main frame
            main_frame = None
            for child in self.root.winfo_children():
                if isinstance(child, ttk.Frame):
                    main_frame = child
                    break

            if not main_frame:
                print("Could not find main frame for pie chart integration")
                return

            # Look for existing notebook or create one
            notebook = None
            for child in main_frame.winfo_children():
                if isinstance(child, ttk.Notebook):
                    notebook = child
                    break

            if not notebook:
                # Create a notebook if one doesn't exist
                # We'll add it after the stats frame
                stats_frame = None
                for child in main_frame.winfo_children():
                    if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Statistics":
                        stats_frame = child
                        break

                if stats_frame:
                    notebook = ttk.Notebook(main_frame)
                    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, after=stats_frame)

            if notebook:
                # Create a frame for the pie chart
                pie_chart_frame = ttk.Frame(notebook, padding="10")
                notebook.add(pie_chart_frame, text="Protocol Chart")

                # Add the pie chart to the frame
                self.protocol_pie_chart = ProtocolPieChart(pie_chart_frame)
                self.protocol_pie_chart.pack(fill=tk.BOTH, expand=True)

                print("Pie chart successfully integrated into UI")
            else:
                print("Could not create or find notebook for pie chart")

        except Exception as e:
            print(f"Error integrating pie chart: {e}")

    # Store original update_protocol_counts method
    original_update_protocol_counts = ui_class.update_protocol_counts

    def enhanced_update_protocol_counts(self, protocol_counts):
        """Enhanced update_protocol_counts method"""
        try:
            # Call original method
            original_update_protocol_counts(self, protocol_counts)

            # Update pie chart if it exists
            if hasattr(self, 'protocol_pie_chart') and self.protocol_pie_chart is not None:
                self.protocol_pie_chart.update_plot(protocol_counts)

        except Exception as e:
            print(f"Error in enhanced_update_protocol_counts: {e}")

    # Replace methods in the class
    ui_class.setup_ui = enhanced_setup_ui
    ui_class.update_protocol_counts = enhanced_update_protocol_counts

    return ui_class