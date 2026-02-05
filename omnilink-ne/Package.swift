// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OmniLinkNE",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        // The Network Extension system extension
        .library(
            name: "OmniLinkExtension",
            type: .dynamic,
            targets: ["OmniLinkExtension"]
        ),
        // Helper CLI for Tauri integration
        .executable(
            name: "omnilink-ne-helper",
            targets: ["OmniLinkHelper"]
        ),
    ],
    targets: [
        // Shared code between app and extension
        .target(
            name: "Shared",
            path: "Shared"
        ),
        // Network Extension implementation
        .target(
            name: "OmniLinkExtension",
            dependencies: ["Shared"],
            path: "OmniLinkExtension"
        ),
        // Container app code
        .target(
            name: "OmniLinkApp",
            dependencies: ["Shared"],
            path: "OmniLinkApp"
        ),
        // Helper CLI
        .executableTarget(
            name: "OmniLinkHelper",
            dependencies: ["OmniLinkApp"],
            path: "OmniLinkHelper"
        ),
    ]
)
