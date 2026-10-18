//
//  Authentication.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import GSACryptoKit

private enum PushedCodeState {
    @TaskLocal static var handled = false
}

public extension DeveloperPortal {

    func authenticate(appleID unsanitizedAppleID: String,
                      password: String,
                      anisetteData: AnisetteData,
                      xcodeVersion: String,
                      machinePassword: String? = nil,
                      accountRepairHandler: DeveloperPortal.AccountRepairHandler = DeveloperPortal.defaultAccountRepairHandler,
                      verificationHandler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession
    {
        // Temporary: full file too large for single API call; see patches/SideSign-Authentication-Windows-GSA.swift
        fatalerror("Use patches/SideSign-Authentication-Windows-GSA.swift instructions - full Authentication.swift patch pending")
    }
}
