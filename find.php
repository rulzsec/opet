<?php
// ==============================
// 🛡️ PHP Shell Tarayıcı v2.0
// ==============================

// Session başlat
session_start();

// Hata raporlamayı aktif et
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Çıktı tamponlama - JSON yanıtlar için önemli
ob_start();

// Maksimum çalışma süresi
@set_time_limit(600); // 10 dakikaya yükseltildi (300->600)

// Varsayılan dizin - script'in bulunduğu dizin
$scan_dir = __DIR__;

// Şüpheli fonksiyonlar
$suspicious_functions = array(
    'eval' => 10,
    'exec' => 9,
    'shell_exec' => 9,
    'system' => 9,
    'passthru' => 9,
    'assert' => 8,
    'create_function' => 7,
    'base64_decode' => 6,
    'gzinflate' => 6,
    'str_rot13' => 5,
    'move_uploaded_file' => 7
);

// Şüpheli anahtar kelimeler
$suspicious_keywords = array(
    'c99shell' => 10,
    'r57shell' => 10,
    'web shell' => 9,
    'shell' => 7,
    'backdoor' => 8,
    'hacked' => 6,
    'FilesMan' => 9,
    'WSO' => 9,
    'cmd=' => 8,
    'uname -a' => 7
);

// Şüpheli değişkenler
$suspicious_variables = array(
    '$_GET["cmd"]' => 10,
    '$_POST["cmd"]' => 10,
    '$_REQUEST["cmd"]' => 10,
    '$_FILES' => 6,
    '$_GET["pass"]' => 7,
    '$_POST["pass"]' => 7
);

// Taranan dosya uzantıları
$file_extensions = array('php', 'phtml', 'php3', 'php4', 'php5', 'inc');

// Tarama yapılacak mı?
$do_scan = isset($_POST['start_scan']) && $_POST['start_scan'] == 1;

// Sonuçları depolamak için array
$results = array();

// Dosya tarama fonksiyonu
function scan_file($file) {
    global $suspicious_functions, $suspicious_keywords, $suspicious_variables;
    
    // Çok büyük dosyaları atla (1MB)
    if (filesize($file) > 1048576) {
        return array('score' => 0, 'alerts' => array());
    }
    
    // Dosya içeriğini al
    $content = @file_get_contents($file);
    if ($content === false) {
        return array('score' => 0, 'alerts' => array());
    }
    
    $alerts = array();
    $score = 0;
    
    // Obfuscated kod kontrolü
    if (strlen($content) > 1000 && substr_count($content, "n") < 5) {
        $alerts[] = "Şüpheli obfuscated kod";
        $score += 40;
    }
    
    // Hata raporlama kapatılmış mı?
    if (stripos($content, 'error_reporting(0)') !== false) {
        $alerts[] = "Hata raporlama kapatılmış";
        $score += 15;
    }
    
    // Şüpheli fonksiyonlar
    foreach ($suspicious_functions as $func => $weight) {
        if (stripos($content, $func) !== false) {
            $alerts[] = "Şüpheli fonksiyon: $func";
            $score += $weight;
        }
    }
    
    // Şüpheli anahtar kelimeler
    foreach ($suspicious_keywords as $keyword => $weight) {
        if (stripos($content, $keyword) !== false) {
            $alerts[] = "Şüpheli kelime: $keyword";
            $score += $weight;
        }
    }
    
    // Şüpheli değişkenler
    foreach ($suspicious_variables as $var => $weight) {
        if (stripos($content, $var) !== false) {
            $alerts[] = "Şüpheli değişken: $var";
            $score += $weight;
        }
    }
    
    // Base64 kodlanmış içerik kontrolü
    if (preg_match('/[a-zA-Z0-9/+]{100,}={0,2}/', $content)) {
        $alerts[] = "Uzun base64 kodlanmış içerik";
        $score += 30;
    }
    
    return array('score' => $score, 'alerts' => $alerts);
}

// Tüm dizin ve alt dizinleri tara
function get_all_files($dir) {
    global $file_extensions;
    
    $files_to_scan = array();
    
    try {
        $dir_iterator = new RecursiveDirectoryIterator($dir);
        $iterator = new RecursiveIteratorIterator($dir_iterator);
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $extension = strtolower(pathinfo($file->getPathname(), PATHINFO_EXTENSION));
                if (in_array($extension, $file_extensions)) {
                    $files_to_scan[] = $file->getPathname();
                }
            }
        }
    } catch (Exception $e) {
        // Dizin okunamadıysa boş dizi döndür
    }
    
    return $files_to_scan;
}

// AJAX tarama işlemi
if (isset($_POST['ajax_scan'])) {
    // Önceki çıktıları temizle
    ob_clean();
    
    // AJAX isteğine JSON olarak cevap ver
    header('Content-Type: application/json');
    
    try {
        // Session'daki dosya listesini kullan
        $all_files = isset($_SESSION['files_to_scan']) ? $_SESSION['files_to_scan'] : array();
        if (empty($all_files)) {
            throw new Exception("Dosya listesi bulunamadı. Taramayı yeniden başlatın.");
        }
        
        $current_index = isset($_POST['current_index']) ? (int)$_POST['current_index'] : 0;
        $batch_size = 100; // Daha hızlı tarama için 100 dosya (önceden 15)
        $start_time = isset($_POST['start_time']) ? (float)$_POST['start_time'] : microtime(true);
        
        $total_files = count($all_files);
        
        if ($current_index >= $total_files) {
            echo json_encode(array(
                'status' => 'completed',
                'progress' => 100,
                'message' => 'Tarama tamamlandı.'
            ));
            exit;
        }
        
        $end_index = min($current_index + $batch_size, $total_files);
        $batch_results = array();
        $scanned_files = array();
        
        $batch_start_time = microtime(true);
        
        for ($i = $current_index; $i < $end_index; $i++) {
            if (!isset($all_files[$i])) continue;
            
            $file = $all_files[$i];
            
            // Dosya var mı kontrol et
            if (!file_exists($file)) continue;
            
            $result = scan_file($file);
            
            // Taranan dosyaları takip et (kısa dosya adı)
            $scanned_files[] = basename($file);
            
            if ($result['score'] > 0) {
                $batch_results[] = array(
                    'file' => $file,
                    'score' => $result['score'],
                    'alerts' => $result['alerts']
                );
            }
        }
        
        $batch_time = microtime(true) - $batch_start_time;
        $elapsed_time = microtime(true) - $start_time;
        $progress = round(($end_index / $total_files) * 100);
        
        // Tahmini kalan süre hesapla
        $avg_time_per_file = $elapsed_time / $end_index;
        $remaining_files = $total_files - $end_index;
        $estimated_remaining_time = $remaining_files * $avg_time_per_file;
        
        // Kalan süreyi formatlı hale getir
        $remaining_time_formatted = '';
        if ($estimated_remaining_time > 60) {
            $minutes = floor($estimated_remaining_time / 60);
            $seconds = round($estimated_remaining_time % 60);
            $remaining_time_formatted = "$minutes dk $seconds sn";
        } else {
            $remaining_time_formatted = round($estimated_remaining_time) . " sn";
        }
        
        // JSON çıktısı öncesi tamponları temizle
        ob_clean();
        
        echo json_encode(array(
            'status' => 'in_progress',
            'progress' => $progress,
            'current_index' => $end_index,
            'results' => $batch_results,
            'scanned_files' => $scanned_files,
            'start_time' => $start_time,
            'elapsed_time' => round($elapsed_time),
            'estimated_remaining_time' => $remaining_time_formatted,
            'message' => "Taranan: $end_index / $total_files ($progress%) - Tahmini kalan süre: $remaining_time_formatted"
        ));
    } catch (Exception $e) {
        // Hata oluştuğunda JSON hata mesajı döndür
        ob_clean();
        echo json_encode(array(
            'status' => 'error',
            'error' => $e->getMessage()
        ));
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>PHP Shell Tarayıcı v2.0</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            display: flex;
            align-items: center;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .header-icon {
            font-size: 24px;
            margin-right: 10px;
            color: #007bff;
        }
        h1 {
            color: #333;
            margin: 0;
        }
        .controls {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }
        .control-group {
            margin-right: 15px;
        }
        label {
            margin-right: 5px;
            font-weight: bold;
        }
        input, select, button {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #45a049;
        }
        button#stop-scan {
            background: #f44336;
        }
        button#stop-scan:hover {
            background: #d32f2f;
        }
        .progress-container {
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            overflow: hidden;
            height: 30px;
            position: relative;
            background: #f0f0f0;
        }
        .progress-bar {
            height: 100%;
            background: #4CAF50;
            width: 0%;
            transition: width 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 1px rgba(0,0,0,0.3);
            position: absolute;
            top: 0;
            left: 0;
        }
        .results {
            margin-top: 20px;
        }
        .file {
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
        }
        .high {
            background-color: #ffebee;
            border-left: 5px solid #f44336;
        }
        .medium {
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
        }
        .low {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
        }
        .file-header {
            margin-bottom: 10px;
        }
        .file-path {
            font-weight: bold;
            word-break: break-all;
        }
        .file-score {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
            margin-left: 5px;
        }
        .score-high {
            background-color: #f44336;
        }
        .score-medium {
            background-color: #ffc107;
            color: #333;
        }
        .score-low {
            background-color: #4caf50;
        }
        .alerts {
            background: rgba(255,255,255,0.5);
            padding: 10px;
            border-radius: 4px;
        }
        .alert-item {
            padding: 3px 0;
        }
        .hidden {
            display: none;
        }
        .status {
            margin: 10px 0;
            padding: 10px;
            border-radius: 4px;
            background: #e3f2fd;
            border-left: 5px solid #2196f3;
        }
        .activity-log-container {
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            background: #f8f9fa;
        }
        .activity-log {
            max-height: 200px;
            overflow-y: auto;
            padding: 10px;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            background: #fff;
            font-family: monospace;
            font-size: 13px;
        }
        .log-entry {
            margin: 3px 0;
            padding: 3px 6px;
            border-radius: 3px;
        }
        .log-entry.scanning {
            background-color: #e3f2fd;
            border-left: 3px solid #2196f3;
        }
        .log-entry.found {
            background-color: #ffebee;
            border-left: 3px solid #f44336;
        }
        .log-entry:nth-child(odd) {
            background-color: rgba(0,0,0,0.02);
        }
        .timestamp {
            color: #666;
            font-size: 11px;
            margin-right: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-icon">🛡️</div>
            <h1>PHP Shell Tarayıcı v2.0</h1>
        </div>
        
        <div class="controls">
            <div class="control-group">
                <button id="start-scan">Taramayı Başlat</button>
                <button id="stop-scan" class="hidden">Taramayı Durdur</button>
            </div>
        </div>
        
        <div id="status-message" class="status hidden"></div>
        
        <div id="progress-container" class="progress-container hidden">
            <div id="progress-bar" class="progress-bar">0%</div>
        </div>
        
        <div id="activity-log-container" class="activity-log-container hidden">
            <h3>Tarama Aktivitesi</h3>
            <div id="activity-log" class="activity-log"></div>
        </div>
        
        <div id="results" class="results"></div>
    </div>
    
    <script>
        // Global değişkenler
        let scanInProgress = false;
        let allFiles = []; // Bu artık sadece dosya sayısını takip etmek için
        let totalFiles = 0;
        let currentIndex = 0;
        let allResults = [];
        let stopRequested = false;
        let startTime = 0;
        
        // DOM elementleri
        const startScanBtn = document.getElementById('start-scan');
        const stopScanBtn = document.getElementById('stop-scan');
        const progressContainer = document.getElementById('progress-container');
        const progressBar = document.getElementById('progress-bar');
        const resultsContainer = document.getElementById('results');
        const statusMessage = document.getElementById('status-message');
        const activityLogContainer = document.getElementById('activity-log-container');
        const activityLog = document.getElementById('activity-log');
        
        // Taramayı başlat
        startScanBtn.addEventListener('click', function() {
            if (scanInProgress) return;
            
            scanInProgress = true;
            startScanBtn.classList.add('hidden');
            stopScanBtn.classList.remove('hidden');
            progressContainer.classList.remove('hidden');
            activityLogContainer.classList.remove('hidden');
            statusMessage.classList.remove('hidden');
            statusMessage.textContent = 'Dosyalar hazırlanıyor...';
            activityLog.innerHTML = '';
            allResults = [];
            stopRequested = false;
            
            // Başlangıç zamanını kaydet
            startTime = Date.now() / 1000; // saniye cinsinden
            
            // Önce tüm dosyaları topla
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'start_scan=1'
            })
            .then(response => response.text())
            .then(html => {
                // Burada sayfanın HTML içeriğini analiz ederek dosya listesini çıkaracağız
                // Bu yaklaşım hosting kısıtlamaları nedeniyle AJAX öncesi dönüşü kullanır
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = html;
                const filesData = tempDiv.querySelector('#files-data');
                
                if (filesData) {
                    try {
                        totalFiles = parseInt(filesData.textContent || '0');
                        currentIndex = 0;
                        statusMessage.textContent = `Toplam ${totalFiles} dosya taranacak.`;
                        console.log('Dosya listesi alındı, dosya sayısı:', totalFiles);
                        
                        if (totalFiles > 0) {
                            console.log('Tarama başlatılıyor...');
                            processNextBatch();
                        } else {
                            finishScan('Taranacak dosya bulunamadı.');
                        }
                    } catch (e) {
                        console.error('Dosya listesi hatası:', e);
                        finishScan('Dosya listesi alınamadı: ' + e.message);
                    }
                } else {
                    finishScan('Dosya listesi bulunamadı.');
                }
            })
            .catch(error => {
                console.error('Başlangıç hatası:', error);
                finishScan('Hata: ' + error.message);
            });
        });
        
        // Taramayı durdur
        stopScanBtn.addEventListener('click', function() {
            stopRequested = true;
            statusMessage.textContent = 'Tarama durduruluyor...';
        });
        
        // Sonraki batch'i işle
        function processNextBatch() {
            if (stopRequested) {
                finishScan('Tarama kullanıcı tarafından durduruldu.');
                return;
            }
            
            if (currentIndex >= totalFiles) {
                finishScan('Tarama tamamlandı.');
                return;
            }
            
            // Debug: konsola bilgi yaz
            console.log('Batch işleme başladı:', currentIndex, 'Toplam:', totalFiles);
            statusMessage.textContent = 'Dosyalar işleniyor... ' + currentIndex + ' / ' + totalFiles;
            
            // Yalnızca indeksleri gönderelim, tüm dosya listesini değil
            const startTime = Date.now();
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'ajax_scan=1&current_index=' + currentIndex + '&start_time=' + startTime
            })
            .then(response => {
                console.log('AJAX yanıtı alındı:', response.status, 'Süre:', Date.now() - startTime, 'ms');
                if (!response.ok) {
                    throw new Error('Sunucu hatası: ' + response.status);
                }
                return response.text().then(text => {
                    console.log('Yanıt uzunluğu:', text.length, 'karakterler');
                    if (text.length === 0) {
                        throw new Error('Boş yanıt alındı');
                    }
                    
                    if (text.startsWith('<!DOCTYPE') || text.startsWith('<html')) {
                        console.error('HTML yanıtı alındı, JSON bekleniyor');
                        throw new Error('AJAX yanıtı JSON değil HTML olarak döndü');
                    }
                    
                    try {
                        // Önce JSON olarak ayrıştırmayı dene
                        return JSON.parse(text);
                    } catch (e) {
                        // JSON ayrıştırma hatası oluştuysa, yanıtı göster
                        console.error('JSON ayrıştırma hatası:', e);
                        console.log('Sunucu yanıtı (ilk 500 karakter):', text.substring(0, 500));
                        throw new Error('JSON ayrıştırma hatası: ' + e.message);
                    }
                });
            })
            .then(data => {
                if (!data) {
                    throw new Error('Veri alınamadı');
                }
                
                console.log('İşlenecek data alındı:', data);
                
                if (!data.status) {
                    throw new Error('Yanıtta durum bilgisi eksik');
                }
                
                updateProgress(data.progress);
                
                // Taranan dosyaları log'a ekle
                if (data.scanned_files && data.scanned_files.length > 0) {
                    updateActivityLog(data.scanned_files, data.results);
                }
                
                if (data.results && data.results.length > 0) {
                    allResults = allResults.concat(data.results);
                    displayResults();
                }
                
                currentIndex = data.current_index;
                statusMessage.textContent = data.message;
                
                if (data.status === 'completed') {
                    finishScan('Tarama tamamlandı.');
                } else {
                    // Batch işleme tamamlandığında, anında sonraki batch'i işle
                    setTimeout(processNextBatch, 0);
                }
            })
            .catch(error => {
                console.error('AJAX hatası:', error);
                statusMessage.textContent = 'Hata: ' + error.message;
                
                // Ciddi hata durumunda taramayı sonlandır
                finishScan('Hata: ' + error.message);
            });
        }
        
        // İlerlemeyi güncelle
        function updateProgress(percentage) {
            percentage = Math.min(100, Math.max(0, percentage)); // 0-100 arasında sınırla
            progressBar.style.width = percentage + '%';
            progressBar.textContent = percentage + '%';
        }
        
        // Sonuçları göster
        function displayResults() {
            // Önce sonuçları skora göre sırala
            allResults.sort((a, b) => b.score - a.score);
            
            // Sonuçları temizle ve yeniden göster
            resultsContainer.innerHTML = '';
            
            if (allResults.length === 0) {
                resultsContainer.innerHTML = '<p>Hiçbir şüpheli dosya bulunamadı.</p>';
                return;
            }
            
            for (let result of allResults) {
                let riskClass = 'low';
                let riskLevel = 'Düşük';
                let scoreClass = 'score-low';
                
                if (result.score >= 40) {
                    riskClass = 'high';
                    riskLevel = 'Yüksek';
                    scoreClass = 'score-high';
                } else if (result.score >= 20) {
                    riskClass = 'medium';
                    riskLevel = 'Orta';
                    scoreClass = 'score-medium';
                }
                
                const fileDiv = document.createElement('div');
                fileDiv.className = `file ${riskClass}`;
                
                const fileHeader = document.createElement('div');
                fileHeader.className = 'file-header';
                
                const filePath = document.createElement('div');
                filePath.className = 'file-path';
                filePath.textContent = result.file;
                
                const fileScore = document.createElement('span');
                fileScore.className = `file-score ${scoreClass}`;
                fileScore.textContent = `Risk: ${riskLevel} (${result.score})`;
                
                fileHeader.appendChild(filePath);
                fileHeader.appendChild(fileScore);
                
                const alertsDiv = document.createElement('div');
                alertsDiv.className = 'alerts';
                
                const alertsList = document.createElement('ul');
                result.alerts.forEach(alert => {
                    const alertItem = document.createElement('li');
                    alertItem.className = 'alert-item';
                    alertItem.textContent = alert;
                    alertsList.appendChild(alertItem);
                });
                
                alertsDiv.appendChild(alertsList);
                
                fileDiv.appendChild(fileHeader);
                fileDiv.appendChild(alertsDiv);
                
                resultsContainer.appendChild(fileDiv);
            }
        }
        
        // Taramayı bitir
        function finishScan(message) {
            scanInProgress = false;
            stopScanBtn.classList.add('hidden');
            startScanBtn.classList.remove('hidden');
            statusMessage.textContent = message;
            
            // Tamamlandı olarak göster
            updateProgress(100);
        }
        
        // Aktivite log'unu güncelle
        function updateActivityLog(scannedFiles, results) {
            // Sonuç olarak bulunan dosya adlarını al
            const foundFiles = results ? results.map(r => basename(r.file)) : [];
            
            scannedFiles.forEach(file => {
                const isFound = foundFiles.includes(file);
                const logEntry = document.createElement('div');
                logEntry.className = 'log-entry ' + (isFound ? 'found' : 'scanning');
                
                // Zaman damgası
                const now = new Date();
                const timestamp = now.getHours().toString().padStart(2, '0') + ':' + 
                                 now.getMinutes().toString().padStart(2, '0') + ':' + 
                                 now.getSeconds().toString().padStart(2, '0');
                
                // Log mesajı
                logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> Tarandı: ${file}` + 
                                   (isFound ? ' <strong>⚠️ Şüpheli!</strong>' : '');
                
                // En üste ekle
                if (activityLog.firstChild) {
                    activityLog.insertBefore(logEntry, activityLog.firstChild);
                } else {
                    activityLog.appendChild(logEntry);
                }
                
                // Maximum 100 log göster
                if (activityLog.children.length > 100) {
                    activityLog.removeChild(activityLog.lastChild);
                }
            });
            
            // Otomatik scroll
            activityLog.scrollTop = 0;
        }
        
        // Dosya adı kısa yol fonksiyonu
        function basename(path) {
            return path.split(/[\/]/).pop();
        }
    </script>
    
    <?php
    // Tarama başlatıldıysa dosya listesini session'a kaydet
    if ($do_scan) {
        $files_to_scan = get_all_files($scan_dir);
        $_SESSION['files_to_scan'] = $files_to_scan;
        echo '<script id="files-data" type="application/json">' . count($files_to_scan) . '</script>';
    }
    ?>
</body>
</html>