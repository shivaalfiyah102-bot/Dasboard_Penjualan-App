# Gambar Tampilan Admin

<img width="1917" height="1030" alt="input admin" src="https://github.com/user-attachments/assets/56c19c2e-255f-44bc-82c2-347001a8064c" />

# Dashboard Penjualan Berbasis Streamlit

Aplikasi ini merupakan dashboard penjualan berbasis web yang dikembangkan menggunakan framework **Streamlit**. Aplikasi digunakan untuk menampilkan dan menganalisis data penjualan secara interaktif melalui visualisasi dan tabel, serta dilengkapi dengan sistem autentikasi pengguna.

## Fitur Utama

- Dashboard interaktif berbasis web

- Visualisasi data penjualan

- Sistem login dan manajemen sesi pengguna

- Pengolahan data menggunakan database SQLite

- Dapat diakses secara online tanpa menggunakan localhost

## Struktur Direktori

Struktur direktori aplikasi disusun sesuai dengan standar deployment Streamlit Cloud sebagai berikut:

DASBOARD/

├── app.py

├── requirements.txt

└── sales_data.db

Keterangan:

- `app.py` : File utama (entry point) aplikasi Streamlit

- `requirements.txt` : Daftar library Python yang dibutuhkan

- `sales_data.db` : Database SQLite yang menyimpan data penjualan

## Teknologi yang Digunakan

- Python

- Streamlit

- Pandas

- Plotly

- SQLite

## Cara Menjalankan Aplikasi Secara Lokal

1. Pastikan Python telah terinstal

2. Install dependensi:
   
   ```bash
   
   pip install -r requirements.txt

3. Jalankan aplikasi:

    ```bash

    streamlit run app.py

4. Akses aplikasi melalui browser pada alamat:

    http://localhost:8501
    
##  Deployment

Aplikasi ini dideploy menggunakan Streamlit Community Cloud.
File app.py dan requirements.txt ditempatkan pada root repository agar aplikasi dapat berjalan dengan baik pada lingkungan cloud tanpa menggunakan server lokal.

##  Catatan

1. Database SQLite digunakan untuk kebutuhan demonstrasi dan analisis data.

2. Data tidak bersifat permanen jika aplikasi di-restart pada lingkungan cloud.

3. Aplikasi ini ditujukan untuk keperluan pembelajaran, tugas kuliah, atau demonstrasi sistem.

##  Penulis
KELOMPOK 5
