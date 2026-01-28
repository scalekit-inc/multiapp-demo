//
//  ContentView.swift
//
//  Created by Akshay Parihar on 23/01/26.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var auth = AuthService()

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Example App (iOS)")
                    .font(.title2)
                    .bold()

                Text("Status: \(auth.status)")
                    .font(.subheadline)

                if let exp = auth.expiresAt {
                    Text("Expires: \(exp.formatted())")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                HStack {
                    Button("Login") { auth.login() }
                    Button("Refresh") {
                        Task { await auth.refresh(force: true) }
                    }
                    Button("Logout") { auth.logout() }
                }

                Text("Access Token Claims")
                    .font(.headline)

                ScrollView {
                    Text(auth.accessPayload.isEmpty ? "(none)" : auth.accessPayload)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(10)
                }
            }
            .padding()
            .onAppear { auth.bootstrap() }
        }
    }
}
