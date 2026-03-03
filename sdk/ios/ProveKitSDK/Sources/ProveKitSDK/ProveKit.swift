import Foundation

public enum ProveKit {
    
    private static var _isInitialized = false
    
    public static var isInitialized: Bool {
        _isInitialized
    }
    
    public static func initialize() throws {
        try FFIBridge.initialize()
        _isInitialized = true
    }
}
