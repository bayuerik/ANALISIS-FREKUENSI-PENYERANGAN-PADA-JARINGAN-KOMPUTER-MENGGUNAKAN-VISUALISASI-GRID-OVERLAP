import os
from scapy.all import rdpcap, TCP
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from pyecharts import options as opts
from pyecharts.charts import Bar, Grid

def scan_file(file_path, summary_results, byte_results):
    packets = rdpcap(file_path)

    ip_count = defaultdict(int)
    ip_byte_count = defaultdict(int)

    for packet in packets:
        if packet.haslayer(TCP) and (packet[TCP].flags & 0x12) == 0x12:
            source_ip = packet["IP"].src
            ip_count[source_ip] += 1
            ip_byte_count[source_ip] += len(packet)

    summary_results[file_path] = ip_count
    byte_results[file_path] = ip_byte_count

    return list(ip_count.keys()), list(ip_count.values())

# Replace 'PCAP' with the path to your folder
folder_path = 'PCAP'

# Dictionary to store scan results
summary_results = {}
byte_results = {}

# List to collect thread results
futures = []

# Maximum number of threads to use
max_threads = 9

# Using ThreadPoolExecutor for scanning in separate threads
with ThreadPoolExecutor(max_threads) as executor:
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.pcap'):
                file_path = os.path.join(root, file_name)
                future = executor.submit(scan_file, file_path, summary_results, byte_results)
                futures.append(future)

    # Using tqdm to track progress
    for future in tqdm(futures, total=len(futures), desc="Scanning Progress", unit="file"):
        source_ips, frequencies = future.result()

# Create a directory for information files
info_dir = "info_files"
os.makedirs(info_dir, exist_ok=True)

# Sort scan results by frequency from highest to lowest
merged_count_results = defaultdict(int)
merged_byte_results = defaultdict(int)

# Save summary information in the summary.txt file
with open("summary.txt", 'w') as summary_output:
    for file_path, count_result in summary_results.items():
        for source_ip, count in count_result.items():
            merged_count_results[source_ip] += count
            merged_byte_results[source_ip] += byte_results[file_path][source_ip]

        # Menyusun informasi untuk file .txt yang sesuai
        info_file = os.path.join(info_dir, f"info_{os.path.basename(file_path).replace('.pcap', '.txt')}")
        with open(info_file, 'w') as info_output:
            info_output.write(f"Informasi hasil pemindaian untuk {os.path.basename(file_path)}:\n")
            info_output.write(f"Total Alamat IP Sumber: {len(count_result)}\n")
            info_output.write(f"Total Jumlah Byte: {sum(byte_results[file_path].values())}\n")
            info_output.write(f"Alamat IP Sumber dengan Frekuensi Tertinggi: {max(count_result, key=count_result.get)}\n")
            info_output.write(f"Rata-Rata Byte: {sum(byte_results[file_path].values()) / len(count_result)}\n")
            info_output.write(f"Jumlah Frekuensi: {sum(count_result.values())}\n")

            # Menulis informasi ke file summary.txt
            summary_output.write(f"Informasi hasil pemindaian untuk {os.path.basename(file_path)}:\n")
            summary_output.write(f"Total Alamat IP Sumber: {len(count_result)}\n")
            summary_output.write(f"Total Jumlah Byte: {sum(byte_results[file_path].values())}\n")
            summary_output.write(f"Alamat IP Sumber dengan Frekuensi Tertinggi: {max(count_result, key=count_result.get)}\n")
            summary_output.write(f"Rata-Rata Byte: {sum(byte_results[file_path].values()) / len(count_result)}\n")
            summary_output.write(f"Jumlah Frekuensi: {sum(count_result.values())}\n")
        summary_output.write('\n')  # Tambahkan baris kosong antara setiap file

# Calculate average byte count
average_byte = {}
for source_ip in merged_byte_results.keys():
    average_byte[source_ip] = merged_byte_results[source_ip] / merged_count_results[source_ip]

# Create a Bar chart for the scan results
bar = (
    Bar()
    .add_xaxis(list(merged_count_results.keys()))
    .add_yaxis("Frekuensi", list(merged_count_results.values()), category_gap="50%")  # Menambahkan jarak antara kategori
    .add_yaxis("Rata-Rata Byte", list(average_byte.values()), yaxis_index=1)
    .set_global_opts(
        title_opts=opts.TitleOpts(title="Ringkasan hasil pemindaian", subtitle="(Diurutkan berdasarkan Frekuensi)"),
        toolbox_opts=opts.ToolboxOpts(),
        datazoom_opts=[opts.DataZoomOpts()],
        legend_opts=opts.LegendOpts(pos_top="15%"),  # Menyesuaikan posisi legend
        tooltip_opts=opts.TooltipOpts(trigger="axis", axis_pointer_type="cross"),  # Menampilkan tooltip
    )
)

# Create a Grid to include the Bar chart
grid_chart = (
    Grid(init_opts=opts.InitOpts(width="1000px", height="600px"))  # Menyesuaikan ukuran grid
    .add(bar, grid_opts=opts.GridOpts(pos_left="10%", pos_right="8%", pos_top="18%", height="60%"))  # Menyesuaikan posisi grid
)

# Render the chart to an HTML file
grid_chart.render("combined_summary.html")

# Read the content of summary.txt
with open("summary.txt", 'r') as summary_file:
    summary_content = summary_file.read()

with open("combined_summary.html", 'r') as combined_summary_file:
    combined_summary_content = combined_summary_file.read()

# Create a list to store Grid charts
grid_charts = []

# Sort scan results by frequency from highest to lowest
merged_count_results = defaultdict(int)
merged_byte_results = defaultdict(int)

# Using tqdm to track progress
for file_path, count_result in tqdm(summary_results.items(), desc="Generating Charts", unit="file"):
    # Create Bar chart for the scan results of this file
    bar_chart = (
        Bar()
        .add_xaxis(list(count_result.keys()))
        .add_yaxis("Frekuensi", list(count_result.values()), category_gap="50%")
        .set_global_opts(
            title_opts=opts.TitleOpts(title=f"Ringkasan hasil pemindaian - {os.path.basename(file_path)}"),
            toolbox_opts=opts.ToolboxOpts(),
            datazoom_opts=[opts.DataZoomOpts()],
            legend_opts=opts.LegendOpts(pos_top="15%"),
            tooltip_opts=opts.TooltipOpts(trigger="axis", axis_pointer_type="cross"),
        )
    )

    # Create Grid to include the Bar chart
    grid_chart = (
        Grid(init_opts=opts.InitOpts(width="1000px", height="600px"))
        .add(bar_chart, grid_opts=opts.GridOpts(pos_left="10%", pos_right="8%", pos_top="18%", height="60%"))
    )

    # Append the Grid chart to the list
    grid_charts.append(grid_chart)

# Combine average byte count results for the final Bar chart
average_byte = {source_ip: merged_byte_results[source_ip] / merged_count_results[source_ip] for source_ip in merged_byte_results.keys()}
final_bar_chart = (
    Bar()
    .add_xaxis(list(merged_count_results.keys()))
    .add_yaxis("Frekuensi", list(merged_count_results.values()), category_gap="50%")
    .add_yaxis("Rata-Rata Byte", list(average_byte.values()), yaxis_index=1)
    .set_global_opts(
        title_opts=opts.TitleOpts(title="Ringkasan hasil pemindaian", subtitle="(Diurutkan berdasarkan Frekuensi)"),
        toolbox_opts=opts.ToolboxOpts(),
        datazoom_opts=[opts.DataZoomOpts()],
        legend_opts=opts.LegendOpts(pos_top="15%"),
        tooltip_opts=opts.TooltipOpts(trigger="axis", axis_pointer_type="cross"),
    )
)

# Create a Grid to include the final Bar chart
final_grid_chart = (
    Grid(init_opts=opts.InitOpts(width="1000px", height="600px"))
    .add(final_bar_chart, grid_opts=opts.GridOpts(pos_left="10%", pos_right="8%", pos_top="18%", height="60%"))
)

# Update HTML template to include all Grid charts
grid_charts_content = "\n".join([chart.render_embed() for chart in grid_charts])
# %%
html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ANALISIS FREKUENSI PENYERANGAN</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" integrity="sha384-c8mDEPLaG2Cm04u6lGs4RjsqC1paf8QTUSVv4B5/8KUCaVaLzz4eyYacuQYKyax8" crossorigin="anonymous">
    <script type="text/javascript" src="https://assets.pyecharts.org/assets/v5/echarts.min.js"></script>
    <style type="text/css">
        body {{
            font-family: "Arial", sans-serif;
            margin: 0;
            padding: 0;
            background-color: #393E46;
            color: #EEEEEE;
        }}

        header {{
            background-color: #222831;
            color: #00ADB5;
            padding: 10px;
            text-align: center;
        }}

        h1 {{
            text-align: center;
        }}

        main {{
            margin: 8px;
            padding: 8px;
            background-color: #EEEEEE;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            animation: fadeIn 3s  forwards; 
        }}

        h2 {{
            color: #222831;
            border: 2px solid #00ADB5;
            padding: 10px;
            border-radius: 15px;
            overflow: hidden;
            white-space: nowrap;
            animation: fadeIn 4s ease-in-out;
            animation: fadeInWidth 4s linear forwards;
        }}

        p {{
            text-align: left;
            margin-left: 20px;
            line-height: 1.6;
            color: #393E46;
            font-size: 1em;
            font-family: monospace;
            border-right: 5px solid;
            width: 100%;
            white-space: nowrap;
            overflow: hidden;
            display: inline-block;
        }}

        @keyframes fadeIn {{
            from {{
                opacity: 0;
            }}
            to {{
                opacity: 1;
            }}
        }}

        @keyframes fadeInWidth {{
            from {{
                width: 0;
            }}
            to {{
                width: 97%;
            }}
        }}

    </style>
</head>
<body>
    <header>
        <h1>ANALISIS FREKUENSI PENYERANGAN PADA JARINGAN KOMPUTER MENGGUNAKAN VISUALISASI GRID OVERLAP</h1>
    </header>
    <main>
        <section>
            <h2>Deskripsi</h2>
            <p>
                    <span id="deskripsi">Analisis Frekuensi Penyerangan pada Jaringan Komputer menggunakan Visualisasi Grid Overlap <br> 
                    merupakan metode analisis keamanan jaringan yang memanfaatkan teknik visualisasi data berbasis grid.<br> 
                    Dengan menggunakan Teknik ini memungkinkan para administrator jaringan merekam dan merepresentasikan <br> 
                    dalam bentuk grid overlap untuk dengan cepat mengidentifikasi intensitas, melacak serangan, dan <br>
                    mengambil tindakan pencegahan keamanan secara efektif. </span>
            </p>
        </section>
        <section>
            <h2>Hasil Pemindaian Keseluruhan</h2>
            {combined_summary_content}
            <h2>Hasil Pemindaian Individu</h2>
            {grid_charts_content}
<html>
"""
# %%
# Save the combined HTML content to a file
with open("combined_summary_report.html", 'w') as html_output:
    html_output.write(html_template)
