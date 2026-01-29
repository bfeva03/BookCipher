import Foundation

final class OCRViewModel: ObservableObject {
    @Published var recognizedText: String = ""
    private let scanner = OCRScanner()

    func startScanning() {
        scanner.start { [weak self] text in
            DispatchQueue.main.async {
                self?.recognizedText = text
            }
        }
    }
}
