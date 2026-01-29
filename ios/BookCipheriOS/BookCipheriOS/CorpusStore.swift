import Foundation

struct CorpusStore {
    var bookTitles: [String] = []
    var combinedText: String = ""

    mutating func loadBooks(from urls: [URL]) {
        bookTitles = urls.map { $0.lastPathComponent }
        combinedText = ""
        // TODO: Read file contents, normalize, and concatenate.
    }
}
