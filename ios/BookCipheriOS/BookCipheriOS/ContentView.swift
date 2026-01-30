import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            NavigationStack {
                BooksTabView()
            }
            .tabItem {
                Label("Books", systemImage: "books.vertical")
            }

            NavigationStack {
                MainScreenView()
            }
            .tabItem {
                Label("Cipher", systemImage: "lock.shield")
            }
        }
    }
}

struct MainScreenView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case encrypt = "Encrypt"
        case decrypt = "Decrypt"

        var id: String { rawValue }
    }

    @StateObject private var viewModel = OCRViewModel()
    @State private var passphrase = ""
    @State private var outputToken = ""
    @State private var showBooks = false
    @State private var mode: Mode = .encrypt

    var body: some View {
        ZStack {
            Theme.background
                .ignoresSafeArea()

            VStack(spacing: 16) {
                passphraseCard
                booksCard
                modePicker

                VStack(spacing: 12) {
                    if mode == .encrypt {
                        textCard(
                            title: "Plaintext",
                            text: $viewModel.recognizedText,
                            placeholder: "Paste or scan text to encrypt"
                        )
                        .frame(maxHeight: .infinity)
                        outputPanel
                    } else {
                        textCard(
                            title: "Ciphertext",
                            text: $outputToken,
                            placeholder: "Paste token to decrypt"
                        )
                        .frame(maxHeight: .infinity)
                        outputPanel
                    }
                }
                .frame(maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .navigationTitle("BookCipher")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(Theme.panel, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            ActionBarView(
                mode: mode,
                onPrimary: handlePrimary,
                onScan: handleScan,
                onClear: handleClear
            )
            .padding(.bottom, 8)
        }
        .sheet(isPresented: $showBooks) {
            BooksSheet()
        }
    }

    private var booksCard: some View {
        Card(title: "Books") {
            VStack(alignment: .leading, spacing: 10) {
                Text("0 selected • Order matters")
                    .font(.subheadline)
                    .foregroundStyle(Theme.muted)
                Button("Manage Books") {
                    showBooks = true
                }
                .buttonStyle(SecondaryButtonStyle())
            }
        }
    }

    private var modePicker: some View {
        Picker("Mode", selection: $mode) {
            ForEach(Mode.allCases) { mode in
                Text(mode.rawValue).tag(mode)
            }
        }
        .pickerStyle(.segmented)
    }

    private var passphraseCard: some View {
        Card(title: "Passphrase") {
            SecureField("Required for encrypt/decrypt", text: $passphrase)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .padding(12)
                .background(Theme.panel2)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Theme.border, lineWidth: 1)
                )
        }
    }

    private var outputPanel: some View {
        Card(title: "Output") {
            HStack {
                Text(mode == .encrypt ? "Ciphertext ready to copy" : "Plaintext will appear above")
                    .font(.footnote)
                    .foregroundStyle(Theme.muted)
                Spacer()
                Button("Copy") {
                    // TODO: Clipboard integration for token/plaintext.
                }
                .buttonStyle(SecondaryButtonStyle())
            }
        }
    }

    private func textCard(title: String, text: Binding<String>, placeholder: String) -> some View {
        Card(title: title) {
            LabeledEditor(
                placeholder: placeholder,
                text: text
            )
        }
    }

    private func handleScan() {
        viewModel.startScanning()
    }

    private func handlePrimary() {
        switch mode {
        case .encrypt:
            outputToken = CryptoEngine.stubEncrypt(
                plaintext: viewModel.recognizedText,
                passphrase: passphrase
            )
        case .decrypt:
            viewModel.recognizedText = CryptoEngine.stubDecrypt(
                token: outputToken,
                passphrase: passphrase
            )
        }
    }

    private func handleClear() {
        viewModel.recognizedText = ""
        outputToken = ""
    }
}

private struct LabeledEditor: View {
    let placeholder: String
    @Binding var text: String

    var body: some View {
        ZStack(alignment: .topLeading) {
            if text.isEmpty {
                Text(placeholder)
                    .foregroundStyle(Theme.muted)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
            }
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(Theme.fg)
                .scrollContentBackground(.hidden)
                .padding(8)
        }
        .background(Theme.panel2)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Theme.border, lineWidth: 1)
        )
    }
}

private struct Card<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)
                .foregroundStyle(Theme.fg)
            content
        }
        .padding(14)
        .background(Theme.panel)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Theme.border, lineWidth: 1)
        )
    }
}

private struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.fg)
            .padding(.vertical, 10)
            .padding(.horizontal, 14)
            .frame(maxWidth: .infinity)
            .background(Theme.accent.opacity(configuration.isPressed ? 0.8 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

private struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.fg)
            .padding(.vertical, 10)
            .padding(.horizontal, 14)
            .frame(maxWidth: .infinity)
            .background(Theme.panel2.opacity(configuration.isPressed ? 0.8 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(Theme.border, lineWidth: 1)
            )
    }
}

private struct ActionBarView: View {
    let mode: MainScreenView.Mode
    let onPrimary: () -> Void
    let onScan: () -> Void
    let onClear: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Button("Scan") {
                onScan()
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: 90)

            Button(mode == .encrypt ? "Encrypt →" : "← Decrypt") {
                onPrimary()
            }
            .buttonStyle(PrimaryButtonStyle())
            .frame(maxWidth: .infinity)

            Button("Clear") {
                onClear()
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: 90)
        }
        .padding(12)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Theme.border, lineWidth: 1)
        )
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }
}

private enum Theme {
    static let bg = Color(red: 0.07, green: 0.02, blue: 0.04)
    static let panel = Color(red: 0.11, green: 0.04, blue: 0.06)
    static let panel2 = Color(red: 0.13, green: 0.05, blue: 0.07)
    static let accent = Color(red: 0.63, green: 0.07, blue: 0.17)
    static let fg = Color(red: 0.95, green: 0.91, blue: 0.92)
    static let muted = Color(red: 0.74, green: 0.65, blue: 0.68)
    static let border = Color(red: 0.29, green: 0.10, blue: 0.14)

    static var background: LinearGradient {
        LinearGradient(
            gradient: Gradient(colors: [bg, Color(red: 0.10, green: 0.03, blue: 0.05)]),
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }
}

private struct BooksSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section("Selected Books") {
                Text("No books yet.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Books")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Done") {
                    dismiss()
                }
            }
        }
    }
}

private struct BooksTabView: View {
    var body: some View {
        List {
            Section("Selected Books") {
                Text("No books yet.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Books")
    }
}

#Preview {
    ContentView()
}
