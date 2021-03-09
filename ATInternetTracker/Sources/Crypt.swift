/*
This SDK is licensed under the MIT license (MIT)
Copyright (c) 2015- Applied Technologies Internet SAS (registration number B 403 261 258 - Trade and Companies Register of Bordeaux – France)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/





//
//  Crypt.swift
//  Tracker
//
import Foundation

class Crypt: NSObject {

    private static let ACCOUNT = "com.atinternet.encryption.key"

    private static var _encryptionMode = "none"
    static var encryptionMode : String {
        get {
            return _encryptionMode
        }
        set {
            _encryptionMode = newValue
        }
    }

    func encrypt(data: String) -> String? {
        if Crypt._encryptionMode == "none" {
            return data
        }

        #if os(iOS) && !AT_EXTENSION
        return encryption(data: data)
        #elseif os(watchOS)
        if #available(watchOS 6.0, *) {
            return encryption(data: data)
        }
        #elseif os(tvOS)
        if #available(tvOS 13.0, *) {
            return encryption(data: data)
        }
        #endif

        /// if force, we don't use original data
        return Crypt._encryptionMode == "ifcompatible" ? data : nil
    }

    func decrypt(data: String) -> String? {
        #if os(iOS) && !AT_EXTENSION
        return decryption(data: data)
        #elseif os(watchOS)
        if #available(watchOS 6.0, *) {
            return decryption(data: data)
        }
        #elseif os(tvOS)
        if #available(tvOS 13.0, *) {
            return decryption(data: data)
        }
        #endif

        return data
    }

    private func encryption(data: String) -> String? {
        let iv = AES256.randomIv()

        guard let key = getKey(),
            let aes = try? AES256(key: key, iv: iv),
            let sealData = try? aes.encrypt(data.data(using: .utf8)!) else { return nil }

        return sealData.base64EncodedString()
    }

    private func decryption(data: String) -> String? {
        guard let decoded = Data(base64Encoded: data) else {
            return data
        }

        do {
            let iv = AES256.randomIv()

            guard let key = getKey() else { return data }
            let aes = try AES256(key: key, iv: iv)

            return try String(data: aes.decrypt(decoded),
                              encoding: .utf8)
        }
        catch { return data }
    }

    private func getKey() -> Data? {
        let salt = AES256.randomSalt()
        return try? AES256.createKey(password: Crypt.ACCOUNT.data(using: .utf8)!, salt: salt)
    }
}
