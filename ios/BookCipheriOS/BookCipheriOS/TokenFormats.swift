import Foundation

enum TokenFormats {
    static let bc2Prefix = "BC2"
    static let bc3Prefix = "BC3"

    struct ParsedToken {
        let version: String
        let components: [String]
    }

    static func parse(token: String) -> ParsedToken? {
        let parts = token.split(separator: ".").map(String.init)
        guard let version = parts.first, parts.count >= 5 else {
            return nil
        }
        return ParsedToken(version: version, components: parts)
    }
}
