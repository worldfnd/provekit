import SwiftUI
import ProveKit

@main
struct ProveKitDemoApp: App {
    init() {
        // Initialize ProveKit on app launch
        do {
            try ProveKit.initialize()
            print("ProveKit initialized successfully")
        } catch {
            print("Failed to initialize ProveKit: \(error)")
        }
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
