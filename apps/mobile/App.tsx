import React, { useState } from 'react';
import { StyleSheet, Text, View, ScrollView, TouchableOpacity, SafeAreaView, TextInput, Modal, Alert, ActivityIndicator } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator, NativeStackScreenProps } from '@react-navigation/native-stack';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
// Expo SDK 54: uploadAsync lives in the "legacy" entry point
import * as FileSystem from 'expo-file-system/legacy';

// --- CENTRALIZED API CONFIGURATION ---
// Your computer's LAN IP + the backend port (run `ipconfig` to find the IP).
const API_BASE_URL = 'http://10.24.101.39:8000';

// --- SHARED CONTRACT TYPES ---
export type ScannerType = 'qr' | 'vpa' | 'screenshot' | 'url' | 'text' | 'document';
export type VerdictType = 'green' | 'yellow' | 'red' | 'unable_to_verify';
export type ExpectedAction = 'pay' | 'receive' | 'unknown';

export interface Signal {
  code: string;
  severity: 'info' | 'caution' | 'high';
  message: string;
}

export interface ScanResponseEnvelope {
  request_id: string;
  scanner: ScannerType;
  verdict: VerdictType;
  safety_score: number;
  explanation: string;
  signals: Signal[];
  recommended_actions: string[];
  provider_status: string | Record<string, string>;
  can_report: boolean;
}

type RootStackParamList = {
  Home: undefined;
  QRScanner: undefined;
  LinkScanner: undefined;
  MessageScanner: undefined;
  Verdict: { result: ScanResponseEnvelope };
};

const Stack = createNativeStackNavigator<RootStackParamList>();

// --- SMALL HELPER: POST JSON with a timeout so the app never hangs forever ---
async function postJson(path: string, body: object, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    return await response.json();
  } catch (e: any) {
    if (e?.name === 'AbortError') throw new Error('Request timed out. Is the backend running?');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// --- HOME SCREEN ---
function HomeScreen({ navigation }: NativeStackScreenProps<RootStackParamList, 'Home'>) {
  const [busy, setBusy] = useState(false);

  const handleScreenshotScan = async (asset: any) => {
    const response = await FileSystem.uploadAsync(
      `${API_BASE_URL}/api/v1/scan/screenshot`,
      asset.uri,
      {
        fieldName: 'file', // Must match FastAPI parameter: file: UploadFile
        httpMethod: 'POST',
        uploadType: FileSystem.FileSystemUploadType.MULTIPART,
        mimeType: asset.mimeType || 'image/jpeg',
        headers: { Accept: 'application/json' },
      }
    );

    if (response.status !== 200) {
      throw new Error(`Server error (${response.status}): ${response.body}`);
    }
    return JSON.parse(response.body);
  };

  const handlePickImage = async () => {
    try {
      const permissionResult = await ImagePicker.requestMediaLibraryPermissionsAsync();
      if (!permissionResult.granted) {
        Alert.alert('Permission Denied', 'Permission to access your photos is required!');
        return;
      }

      const pickerResult = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ['images'],
        allowsEditing: false,
        quality: 1,
      });

      if (!pickerResult.canceled && pickerResult.assets && pickerResult.assets.length > 0) {
        setBusy(true);
        const result = await handleScreenshotScan(pickerResult.assets[0]);
        navigation.navigate('Verdict', { result });
      }
    } catch (error: any) {
      console.error('Image pick or upload error:', error);
      Alert.alert('Error', `Failed to process screenshot: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.content}>
        <View style={styles.header}>
          <Text style={styles.appName}>ScamShield AI</Text>
          <Text style={styles.tagline}>Real-time Fraud & Scam Detection Engine</Text>
        </View>

        <TouchableOpacity style={[styles.card, styles.cardBlue]} onPress={() => navigation.navigate('QRScanner')}>
          <Text style={styles.cardIcon}>📷</Text>
          <View style={styles.cardTextContainer}>
            <Text style={[styles.cardTitle, { color: '#1E40AF' }]}>Scan QR Code / VPA</Text>
            <Text style={styles.cardSubtext}>Camera QR analysis & VPA paste</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.card, styles.cardPurple]} onPress={handlePickImage} disabled={busy}>
          <Text style={styles.cardIcon}>🖼️</Text>
          <View style={styles.cardTextContainer}>
            <Text style={[styles.cardTitle, { color: '#6D28D9' }]}>Upload Screenshot / Image</Text>
            <Text style={styles.cardSubtext}>{busy ? 'Analyzing image, please wait...' : 'Scan payment receipts & chat logs'}</Text>
          </View>
          {busy && <ActivityIndicator color="#6D28D9" />}
        </TouchableOpacity>

        <TouchableOpacity style={[styles.card, styles.cardAmber]} onPress={() => navigation.navigate('LinkScanner')}>
          <Text style={styles.cardIcon}>🔗</Text>
          <View style={styles.cardTextContainer}>
            <Text style={[styles.cardTitle, { color: '#B45309' }]}>Check Link / APK URL</Text>
            <Text style={styles.cardSubtext}>Safe non-opening domain & APK inspection</Text>
          </View>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.card, styles.cardEmerald]} onPress={() => navigation.navigate('MessageScanner')}>
          <Text style={styles.cardIcon}>💬</Text>
          <View style={styles.cardTextContainer}>
            <Text style={[styles.cardTitle, { color: '#047857' }]}>Analyze Message / Notice</Text>
            <Text style={styles.cardSubtext}>Paste suspicious SMS or WhatsApp text</Text>
          </View>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

// --- QR SCANNER SCREEN ---
function QRScannerScreen({ navigation }: NativeStackScreenProps<RootStackParamList, 'QRScanner'>) {
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);
  const [expectedAction, setExpectedAction] = useState<ExpectedAction>('pay');
  const [manualVpa, setManualVpa] = useState('');

  if (!permission) return <View style={styles.center}><Text>Loading camera...</Text></View>;
  if (!permission.granted) {
    return (
      <View style={styles.center}>
        <Text style={{ textAlign: 'center', marginBottom: 20 }}>Camera permission is required.</Text>
        <TouchableOpacity style={styles.primaryBtn} onPress={requestPermission}>
          <Text style={styles.btnText}>Grant Camera Permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  // The backend expects: { qr_raw, txn_type } where txn_type is 'pay' or 'collect'
  const txnType = expectedAction === 'receive' ? 'collect' : 'pay';

  const handleBarCodeScanned = async ({ data }: { data: string }) => {
    if (scanned) return;
    setScanned(true);

    try {
      const result = await postJson('/api/v1/scan/qr', { qr_raw: data, txn_type: txnType });
      navigation.navigate('Verdict', { result });
    } catch (error: any) {
      console.error('Network Error:', error);
      Alert.alert('Connection Error', `Could not reach the backend: ${error.message}`);
    } finally {
      // allow scanning again when the user comes back to this screen
      setTimeout(() => setScanned(false), 1500);
    }
  };

  const handleManualSubmit = async () => {
    if (!manualVpa.trim()) return;

    try {
      const result = await postJson('/api/v1/scan/vpa', { vpa: manualVpa.trim() });
      navigation.navigate('Verdict', { result });
    } catch (error: any) {
      console.error('Network Error:', error);
      Alert.alert('Connection Error', `Could not reach the backend: ${error.message}`);
    }
  };

  return (
    <View style={{ flex: 1, backgroundColor: '#000' }}>
      <View style={styles.toggleContainer}>
        <Text style={styles.toggleLabel}>I intend to:</Text>
        <View style={styles.toggleGroup}>
          <TouchableOpacity style={[styles.toggleBtn, expectedAction === 'pay' && styles.toggleActive]} onPress={() => setExpectedAction('pay')}>
            <Text style={[styles.toggleText, expectedAction === 'pay' && styles.toggleActiveText]}>Pay Someone</Text>
          </TouchableOpacity>
          <TouchableOpacity style={[styles.toggleBtn, expectedAction === 'receive' && styles.toggleActive]} onPress={() => setExpectedAction('receive')}>
            <Text style={[styles.toggleText, expectedAction === 'receive' && styles.toggleActiveText]}>Receive Money</Text>
          </TouchableOpacity>
        </View>
      </View>

      <CameraView style={StyleSheet.absoluteFill} onBarcodeScanned={scanned ? undefined : handleBarCodeScanned} barcodeScannerSettings={{ barcodeTypes: ['qr'] }} />

      <View style={styles.vpaFallbackBox}>
        <TextInput
          style={styles.vpaInput}
          placeholder="Or paste UPI ID / VPA manually..."
          placeholderTextColor="#9CA3AF"
          value={manualVpa}
          onChangeText={setManualVpa}
          autoCapitalize="none"
          autoCorrect={false}
        />
        <TouchableOpacity style={styles.vpaSubmitBtn} onPress={handleManualSubmit}>
          <Text style={styles.btnText}>Verify</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

// --- LINK SCANNER SCREEN ---
function LinkScannerScreen({ navigation }: NativeStackScreenProps<RootStackParamList, 'LinkScanner'>) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!url.trim()) return;
    setLoading(true);
    try {
      const result = await postJson('/api/v1/scan/url', { url: url.trim() });
      navigation.navigate('Verdict', { result });
    } catch (error: any) {
      console.error('Network Error:', error);
      Alert.alert('Connection Error', `Could not reach backend for URL scan: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.sectionHeader}>Paste URL or App Link</Text>
        <Text style={styles.subtext}>ScamShield parses URL structure safely without navigating to or loading the target page.</Text>
        <TextInput
          style={styles.textArea}
          placeholder="https://example-scam-site.com/login.apk"
          value={url}
          onChangeText={setUrl}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
        />
        <TouchableOpacity style={styles.primaryBtn} onPress={handleAnalyze} disabled={loading}>
          {loading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.btnText}>Analyze Link</Text>}
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

// --- MESSAGE SCANNER SCREEN ---
function MessageScannerScreen({ navigation }: NativeStackScreenProps<RootStackParamList, 'MessageScanner'>) {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    try {
      const result = await postJson('/api/v1/scan/text', { text });
      navigation.navigate('Verdict', { result });
    } catch (error: any) {
      console.error('Network Error:', error);
      Alert.alert('Connection Error', `Could not reach backend for text scan: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.sectionHeader}>Paste Suspicious Text</Text>
        <Text style={styles.subtext}>Paste SMS, WhatsApp messages, or notice copy to detect urgency and phishing signals.</Text>
        <TextInput
          style={[styles.textArea, { height: 120, textAlignVertical: 'top' }]}
          placeholder="e.g. Your electricity bill is unpaid. Power cut tonight at 9 PM. Call 9876543210 immediately."
          multiline
          value={text}
          onChangeText={setText}
        />
        <TouchableOpacity style={styles.primaryBtn} onPress={handleAnalyze} disabled={loading}>
          {loading ? <ActivityIndicator color="#FFF" /> : <Text style={styles.btnText}>Analyze Message</Text>}
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

// --- VERDICT SCREEN WITH REPORT MODAL ---
function VerdictScreen({ route, navigation }: NativeStackScreenProps<RootStackParamList, 'Verdict'>) {
  const { result } = route.params;
  const [reportVisible, setReportVisible] = useState(false);

  const submitReport = async (reason: string) => {
    try {
      // Trailing slash on /reports/ avoids a 307 redirect
      await postJson('/api/v1/reports/', {
        request_id: result?.request_id || 'unknown',
        reason,
      });
      setReportVisible(false);
      Alert.alert('Report Submitted', `Successfully logged under category: ${reason}`);
    } catch (error: any) {
      console.error('Network Error:', error);
      Alert.alert('Connection Error', `Could not submit report: ${error.message}`);
    }
  };

  const safeVerdict = result?.verdict || 'unable_to_verify';

  const getTheme = (verdict: string) => {
    switch (verdict) {
      case 'red': return { bg: '#FEE2E2', icon: '🔴', text: '#EF4444' };
      case 'yellow': return { bg: '#FEF3C7', icon: '🟡', text: '#D97706' };
      case 'green': return { bg: '#D1FAE5', icon: '🟢', text: '#10B981' };
      default: return { bg: '#F3F4F6', icon: '⚪', text: '#6B7280' };
    }
  };

  const theme = getTheme(safeVerdict);

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.content}>
        <View style={[styles.banner, { backgroundColor: theme.bg }]}>
          <Text style={styles.icon}>{theme.icon}</Text>
          <Text style={[styles.title, { color: theme.text }]}>
            {safeVerdict.toUpperCase().replace(/_/g, ' ')}
          </Text>
          <Text style={styles.scoreValue}>Safety Score: {result?.safety_score ?? 0}/100</Text>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionHeader}>Analysis Guidance</Text>
          <Text style={styles.explanationText}>{result?.explanation || 'No explanation provided.'}</Text>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionHeader}>Detected Signals</Text>
          {(result?.signals || []).length === 0 && (
            <Text style={styles.explanationText}>No specific signals detected.</Text>
          )}
          {(result?.signals || []).map((sig, idx) => (
            <View key={idx} style={styles.signalCard}>
              <Text style={styles.signalCode}>[{sig.severity?.toUpperCase() || 'INFO'}] {sig.code || 'UNKNOWN'}</Text>
              <Text style={styles.signalMsg}>{sig.message || ''}</Text>
            </View>
          ))}
        </View>

        {(result?.recommended_actions || []).length > 0 && (
          <View style={styles.section}>
            <Text style={styles.sectionHeader}>What to do</Text>
            {result.recommended_actions.map((a, idx) => (
              <Text key={idx} style={styles.explanationText}>• {a}</Text>
            ))}
          </View>
        )}

        {result?.can_report && (
          <TouchableOpacity style={styles.reportBtn} onPress={() => setReportVisible(true)}>
            <Text style={styles.reportBtnText}>🚨 Report as Fraudulent / Scam</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity style={styles.dismissButton} onPress={() => navigation.navigate('Home')}>
          <Text style={styles.dismissText}>Back to Hub</Text>
        </TouchableOpacity>
      </ScrollView>

      <Modal visible={reportVisible} transparent animationType="slide">
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.sectionHeader}>Submit Fraud Report</Text>
            <Text style={styles.subtext}>Select reason to update synthetic database record:</Text>
            <TouchableOpacity style={styles.modalOption} onPress={() => submitReport('fake_qr')}>
              <Text style={styles.modalOptionText}>Fake QR / Intent Mismatch</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.modalOption} onPress={() => submitReport('phishing')}>
              <Text style={styles.modalOptionText}>Phishing / Impersonation</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.dismissButton} onPress={() => setReportVisible(false)}>
              <Text style={{ color: '#EF4444', fontWeight: '600' }}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Home">
        <Stack.Screen name="Home" component={HomeScreen} options={{ headerShown: false }} />
        <Stack.Screen name="QRScanner" component={QRScannerScreen} options={{ title: 'Scan QR / VPA' }} />
        <Stack.Screen name="LinkScanner" component={LinkScannerScreen} options={{ title: 'Link / URL Check' }} />
        <Stack.Screen name="MessageScanner" component={MessageScannerScreen} options={{ title: 'Message Analysis' }} />
        <Stack.Screen name="Verdict" component={VerdictScreen} options={{ title: 'Scan Verdict' }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F9FAFB' },
  content: { padding: 20 },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20 },
  header: { marginTop: 10, marginBottom: 20 },
  appName: { fontSize: 28, fontWeight: '800', color: '#111827' },
  tagline: { fontSize: 13, color: '#6B7280', marginTop: 2 },
  card: { flexDirection: 'row', alignItems: 'center', padding: 14, borderRadius: 10, marginBottom: 10, borderWidth: 1 },
  cardBlue: { borderColor: '#2563EB', backgroundColor: '#EFF6FF' },
  cardPurple: { borderColor: '#7C3AED', backgroundColor: '#F5F3FF' },
  cardAmber: { borderColor: '#D97706', backgroundColor: '#FEF3C7' },
  cardEmerald: { borderColor: '#059669', backgroundColor: '#ECFDF5' },
  cardIcon: { fontSize: 24, marginRight: 12 },
  cardTextContainer: { flex: 1 },
  cardTitle: { fontSize: 14, fontWeight: '700' },
  cardSubtext: { fontSize: 11, color: '#6B7280', marginTop: 2 },
  toggleContainer: { zIndex: 10, padding: 16, backgroundColor: 'rgba(0,0,0,0.8)', alignItems: 'center' },
  toggleLabel: { color: '#FFF', fontSize: 12, fontWeight: '600', marginBottom: 6 },
  toggleGroup: { flexDirection: 'row', backgroundColor: '#374151', borderRadius: 8, padding: 2 },
  toggleBtn: { paddingVertical: 8, paddingHorizontal: 16, borderRadius: 6 },
  toggleActive: { backgroundColor: '#2563EB' },
  toggleText: { color: '#9CA3AF', fontWeight: '600', fontSize: 12 },
  toggleActiveText: { color: '#FFF' },
  vpaFallbackBox: { position: 'absolute', bottom: 30, left: 20, right: 20, flexDirection: 'row', backgroundColor: '#FFF', borderRadius: 8, padding: 6, elevation: 4 },
  vpaInput: { flex: 1, paddingHorizontal: 10, fontSize: 13, color: '#111827' },
  vpaSubmitBtn: { backgroundColor: '#2563EB', paddingVertical: 8, paddingHorizontal: 14, borderRadius: 6 },
  primaryBtn: { backgroundColor: '#2563EB', padding: 14, borderRadius: 8, alignItems: 'center', marginTop: 12 },
  btnText: { color: '#FFF', fontWeight: '700' },
  textArea: { backgroundColor: '#FFF', borderWidth: 1, borderColor: '#D1D5DB', borderRadius: 8, padding: 12, fontSize: 14, marginTop: 10 },
  subtext: { fontSize: 12, color: '#6B7280', marginTop: 4 },
  sectionHeader: { fontSize: 15, fontWeight: '700', color: '#111827', marginBottom: 4 },
  banner: { padding: 16, borderRadius: 10, alignItems: 'center', marginBottom: 16 },
  icon: { fontSize: 32, marginBottom: 4 },
  title: { fontSize: 18, fontWeight: '800' },
  scoreValue: { fontSize: 16, fontWeight: '800', marginTop: 4, color: '#1F2937' },
  section: { marginBottom: 16 },
  explanationText: { fontSize: 13, color: '#4B5563', lineHeight: 18 },
  signalCard: { backgroundColor: '#FFF', padding: 10, borderRadius: 6, borderWidth: 1, borderColor: '#E5E7EB', marginTop: 6 },
  signalCode: { fontSize: 11, fontWeight: '700', color: '#DC2626' },
  signalMsg: { fontSize: 12, color: '#374151', marginTop: 2 },
  reportBtn: { backgroundColor: '#FEE2E2', padding: 12, borderRadius: 8, alignItems: 'center', borderColor: '#EF4444', borderWidth: 1, marginBottom: 10 },
  reportBtnText: { color: '#DC2626', fontWeight: '700' },
  dismissButton: { padding: 12, alignItems: 'center' },
  dismissText: { color: '#4B5563', fontWeight: '600' },
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'flex-end' },
  modalContent: { backgroundColor: '#FFF', padding: 20, borderTopLeftRadius: 16, borderTopRightRadius: 16 },
  modalOption: { padding: 14, backgroundColor: '#F3F4F6', borderRadius: 8, marginTop: 10 },
  modalOptionText: { fontSize: 14, fontWeight: '600', color: '#1F2937' },
});
