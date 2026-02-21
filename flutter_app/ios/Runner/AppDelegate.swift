import Flutter
import UIKit
import UserNotifications

@main
@objc class AppDelegate: FlutterAppDelegate {
  private var pendingTokenResult: FlutterResult?
  private var lastToken: String?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    if let controller = window?.rootViewController as? FlutterViewController {
      let channel = FlutterMethodChannel(name: "apns", binaryMessenger: controller.binaryMessenger)
      channel.setMethodCallHandler { [weak self] call, result in
        guard let self = self else { return }
        if call.method == "requestToken" {
          self.requestPushToken(result)
        } else {
          result(FlutterMethodNotImplemented)
        }
      }
    }
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  private func requestPushToken(_ result: @escaping FlutterResult) {
    if let token = lastToken {
      result(token)
      return
    }

    pendingTokenResult = result
    UNUserNotificationCenter.current().delegate = self
    UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
      if let error = error {
        result(FlutterError(code: "apns_permission_error", message: error.localizedDescription, details: nil))
        self.pendingTokenResult = nil
        return
      }
      if !granted {
        result(FlutterError(code: "apns_permission_denied", message: "푸시 알림 권한이 필요합니다.", details: nil))
        self.pendingTokenResult = nil
        return
      }
      DispatchQueue.main.async {
        UIApplication.shared.registerForRemoteNotifications()
      }
    }
  }

  override func application(
    _ application: UIApplication,
    didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
  ) {
    let token = deviceToken.map { String(format: "%02x", $0) }.joined()
    lastToken = token
    pendingTokenResult?(token)
    pendingTokenResult = nil
  }

  override func application(
    _ application: UIApplication,
    didFailToRegisterForRemoteNotificationsWithError error: Error
  ) {
    pendingTokenResult?(FlutterError(code: "apns_register_failed", message: error.localizedDescription, details: nil))
    pendingTokenResult = nil
  }
}
