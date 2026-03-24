import AppIntents

/// Entry point for discovering app intents shipped by this package.
public struct LongfellowAppIntentsPackage: AppIntentsPackage {
    public static var includedPackages: [any AppIntentsPackage.Type] {
        []
    }
}
