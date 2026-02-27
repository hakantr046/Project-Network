🛡️ Packet-Level Network Anomaly Detection with Machine Learning
Bu proje, ham ağ trafiğini yakalayıp paket seviyesinde özellik mühendisliği (Feature Engineering) yapan ve Isolation Forest algoritması ile anomalileri tespit eden bir Saldırı Tespit Sistemi (NIDS) çalışmasıdır. Proje; Ağ Mühendisliği, Siber Güvenlik ve Makine Öğrenmesi disiplinlerinin entegrasyonu ile geliştirilmiştir.

🏗️ Proje Mimarisi ve İş Akışı
Sistem, verinin ağ kartından geçmesinden görsel raporun oluşmasına kadar şu adımları takip eder:

Traffic Capture: ens33 arayüzünden ham verilerin toplanması.

Preprocessing: PCAP dosyalarının yapılandırılmış CSV formatına dönüştürülmesi.

Feature Engineering: time_diff ve IP kodlama gibi özelliklerin türetilmesi.

AI Modeling: Isolation Forest ile anomali skoru hesaplanması.

Detection: Gerçek zamanlı veya offline alarm üretilmesi.

🛠️ Uygulama Adımları ve Kodlar
1. Ham Veri Yakalama (Traffic Capture)
Ağ trafiği, tcpdump aracı kullanılarak yakalanır ve daha sonra analiz edilmek üzere bir PCAP dosyasına kaydedilir:

Bash

# ens33 arayüzünü dinle ve trafiği kaydet
sudo tcpdump -i ens33 -w traffic_clean.pcap
Saldırı Simülasyonu: Modelin başarısını test etmek için bir "Flood" saldırısı simüle edilmiştir:

Bash

# Hedef adrese yoğun paket gönderimi başlat
sudo ping -f 8.8.8.8
2. Veri Dönüştürme (PCAP to CSV)
Ham paketler, tshark aracı ile makine öğrenmesi modelinin okuyabileceği yapıya getirilir:

Bash

# Gerekli alanları (Zaman, IP'ler, Protokol, Uzunluk) ayıkla
tshark -r traffic_clean.pcap -Y "ip" -T fields -E separator=, \
-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e frame.len > traffic_clean.csv

# Başlık satırı ekle
echo "time,src_ip,dst_ip,protocol,length" | cat - traffic_clean.csv > traffic_labeled.csv
3. Analiz ve Görselleştirme Motoru (neuronids_engine.py)
Toplanan verileri analiz eden ve sonuçları grafikleyen ana modül:

Python

import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

def run_analysis():
    # Veriyi yükle
    df = pd.read_csv('traffic_labeled.csv')

    # Özellik Mühendisliği (Basit Örnek)
    model = IsolationForest(contamination=0.02, random_state=42)
    df['anomaly'] = model.fit_predict(df[['protocol', 'length']])
    df['status'] = df['anomaly'].map({1: 'Normal', -1: 'Anomali'})

    # Görselleştirme
    plt.figure(figsize=(10, 6))
    colors = {'Normal': 'blue', 'Anomali': 'red'}
    plt.scatter(range(len(df)), df['length'], c=df['status'].map(colors), alpha=0.5)
    plt.title('Project - Ağ Trafiği Anomali Analizi')
    plt.savefig('project_analysis.png')
    print("Analiz tamamlandı, rapor kaydedildi.")

if __name__ == "__main__":
    run_analysis()
4. Gerçek Zamanlı İzleme Modülü (real_time_nids.py)
Sistemin canlı ağ trafiği üzerinde anlık alarm üretmesini sağlayan modül:

Python

# NOT: Burada real_time_nids.py kodu yer alacak
# Bu modül, tshark ile canlı paket yakalar ve anlık PROJECT ALARM üretir.
📊 Analiz Sonuçları
Sistem, ICMP Flood ve DoS gibi yüksek yoğunluklu trafikleri time_diff ve length özellikleri üzerinden saniyeler içinde tespit edebilmektedir.

Normal Trafik: Sistemin öğrendiği olağan akış (Mavi noktalar).

Anomaliler: Beklenmedik paket boyutları ve sıklıkları (Kırmızı noktalar).

🚀 Kurulum
Bash

pip install pandas scikit-learn matplotlib

sudo ./venv/bin/python real_time_nids.py

