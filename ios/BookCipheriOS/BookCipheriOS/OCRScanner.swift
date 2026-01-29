import Foundation

final class OCRScanner {
    typealias OCRHandler = (String) -> Void

    func start(completion: @escaping OCRHandler) {
        // TODO: Replace with AVFoundation + Vision OCR flow.
        completion("Scanned text will appear here.")
    }
}
