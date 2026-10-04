// VibeMessenger - self-hosted end-to-end encrypted messenger.
// Copyright (C) 2026 eliduc
//
// This program is free software: you may redistribute it and/or modify it under
// the terms of the GNU Affero General Public License, version 3, as published by
// the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL v3 <https://www.gnu.org/licenses/agpl-3.0.html>;
// a verbatim copy ships in the LICENSE file at the root of this repository.
//
// AGPL section 13: if you modify this program and let users interact with it
// over a network, you must offer those users the complete corresponding source
// of your modified version, at no charge, from a network server.

/// Application configuration
library;

class AppConfig {
  // Server settings
  static const String serverHost = 'YOUR_SERVER_HOST';  // set to your deployment host
  static const int serverPort = 8443;
  static const bool useHttps = false;
  
  static String get baseUrl => 'http://$serverHost:$serverPort';
  static String get wsUrl => 'ws://$serverHost:$serverPort/ws';
  static String get apiUrl => '$baseUrl/api/v1';
  
  // WebRTC settings
  static const Map<String, dynamic> iceServers = {
    'iceServers': [
      {'urls': 'stun:stun.l.google.com:19302'},
    ],
  };
  
  // Crypto settings
  static const int preKeyBatchSize = 100;
  static const int preKeyReplenishThreshold = 10;
  
  // App settings
  static const String appName = 'Secure Messenger';
  static const String appVersion = '0.1.0';
  
  // Timeouts
  static const Duration connectionTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  static const Duration wsReconnectDelay = Duration(seconds: 5);
}
