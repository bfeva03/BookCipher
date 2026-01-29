import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = OCRViewModel()
    @State private var passphrase = ""
    @State private var outputToken = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Books") {
                    Text("Import or select corpus files.")
                        .foregroundStyle(.secondary)
                    Button("Manage Books") {
                        // TODO: Present document picker or book list.
                    }
                }

                Section("Scanned Text") {
                    TextEditor(text: $viewModel.recognizedText)
                        .frame(minHeight: 120)
                }

                Section("Passphrase") {
                    SecureField("Required for encrypt/decrypt", text: $passphrase)
                }

                Section("Actions") {
                    Button("Scan Text") {
                        viewModel.startScanning()
                    }
                    Button("Encrypt") {
                        outputToken = CryptoEngine.stubEncrypt(
                            plaintext: viewModel.recognizedText,
                            passphrase: passphrase
                        )
                    }
                    Button("Decrypt") {
                        viewModel.recognizedText = CryptoEngine.stubDecrypt(
                            token: outputToken,
                            passphrase: passphrase
                        )
                    }
                }

                Section("Output Token") {
                    TextEditor(text: $outputToken)
                        .frame(minHeight: 120)
                        .font(.footnote)
                }
            }
            .navigationTitle("BookCipher")
        }
    }
}

#Preview {
    ContentView()
}
