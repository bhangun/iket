import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:async';
import 'package:web_socket_channel/web_socket_channel.dart';

void main() {
  runApp(const IketManagementApp());
}

class IketManagementApp extends StatelessWidget {
  const IketManagementApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Iket Management Console',
      theme: ThemeData(primarySwatch: Colors.blue, useMaterial3: true),
      home: const ManagementDashboard(),
    );
  }
}

class ManagementDashboard extends StatefulWidget {
  const ManagementDashboard({super.key});

  @override
  State<ManagementDashboard> createState() => _ManagementDashboardState();
}

class _ManagementDashboardState extends State<ManagementDashboard> {
  final String baseUrl = 'http://localhost:8080/api/v1';
  final String username = 'admin';
  final String password = 'admin123';

  Map<String, dynamic>? gatewayStatus;
  List<Map<String, dynamic>> plugins = [];
  List<Map<String, dynamic>> routes = [];
  List<Map<String, dynamic>> logs = [];

  WebSocketChannel? statusChannel;
  WebSocketChannel? metricsChannel;
  WebSocketChannel? logsChannel;

  Timer? _statusTimer;
  Timer? _metricsTimer;

  @override
  void initState() {
    super.initState();
    _loadInitialData();
    _connectWebSockets();
  }

  @override
  void dispose() {
    _statusTimer?.cancel();
    _metricsTimer?.cancel();
    statusChannel?.sink.close();
    metricsChannel?.sink.close();
    logsChannel?.sink.close();
    super.dispose();
  }

  Future<void> _loadInitialData() async {
    await Future.wait([
      _loadGatewayStatus(),
      _loadPlugins(),
      _loadRoutes(),
      _loadLogs(),
    ]);
  }

  Future<void> _loadGatewayStatus() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/gateway/status'),
        headers: _getAuthHeaders(),
      );

      if (response.statusCode == 200) {
        setState(() {
          gatewayStatus = json.decode(response.body);
        });
      }
    } catch (e) {
      print('Error loading gateway status: $e');
    }
  }

  Future<void> _loadPlugins() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/plugins'),
        headers: _getAuthHeaders(),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          plugins = List<Map<String, dynamic>>.from(data['plugins']);
        });
      }
    } catch (e) {
      print('Error loading plugins: $e');
    }
  }

  Future<void> _loadRoutes() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/routes'),
        headers: _getAuthHeaders(),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          routes = List<Map<String, dynamic>>.from(data['routes']);
        });
      }
    } catch (e) {
      print('Error loading routes: $e');
    }
  }

  Future<void> _loadLogs() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/logs?limit=50'),
        headers: _getAuthHeaders(),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          logs = List<Map<String, dynamic>>.from(data['logs']);
        });
      }
    } catch (e) {
      print('Error loading logs: $e');
    }
  }

  void _connectWebSockets() {
    // Connect to status updates
    statusChannel = WebSocketChannel.connect(
      Uri.parse('ws://localhost:8080/api/v1/ws/status'),
    );

    statusChannel!.stream.listen((message) {
      final data = json.decode(message);
      if (data['type'] == 'status_update') {
        setState(() {
          gatewayStatus = data['data'];
        });
      }
    }, onError: (error) => print('Status WebSocket error: $error'));

    // Connect to metrics updates
    metricsChannel = WebSocketChannel.connect(
      Uri.parse('ws://localhost:8080/api/v1/ws/metrics'),
    );

    metricsChannel!.stream.listen((message) {
      final data = json.decode(message);
      if (data['type'] == 'metrics_update') {
        // Update metrics in real-time
        print('Metrics update: ${data['data']}');
      }
    }, onError: (error) => print('Metrics WebSocket error: $error'));

    // Connect to logs updates
    logsChannel = WebSocketChannel.connect(
      Uri.parse('ws://localhost:8080/api/v1/ws/logs'),
    );

    logsChannel!.stream.listen((message) {
      final data = json.decode(message);
      if (data['type'] == 'log_entry') {
        setState(() {
          logs.insert(0, data['data']);
          if (logs.length > 100) {
            logs.removeLast();
          }
        });
      }
    }, onError: (error) => print('Logs WebSocket error: $error'));
  }

  Map<String, String> _getAuthHeaders() {
    final credentials = base64Encode(utf8.encode('$username:$password'));
    return {
      'Authorization': 'Basic $credentials',
      'Content-Type': 'application/json',
    };
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Iket Management Console'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Row(
        children: [
          // Sidebar
          Container(
            width: 250,
            color: Colors.grey[100],
            child: Column(
              children: [
                _buildSidebarItem('Dashboard', Icons.dashboard, () {}),
                _buildSidebarItem('Gateway', Icons.router, () {}),
                _buildSidebarItem('Plugins', Icons.extension, () {}),
                _buildSidebarItem('Routes', Icons.route, () {}),
                _buildSidebarItem('Logs', Icons.list_alt, () {}),
                _buildSidebarItem('Certificates', Icons.security, () {}),
                _buildSidebarItem('Backup', Icons.backup, () {}),
              ],
            ),
          ),
          // Main content
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildGatewayStatusCard(),
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(child: _buildPluginsCard()),
                      const SizedBox(width: 16),
                      Expanded(child: _buildRoutesCard()),
                    ],
                  ),
                  const SizedBox(height: 16),
                  _buildLogsCard(),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSidebarItem(String title, IconData icon, VoidCallback onTap) {
    return ListTile(leading: Icon(icon), title: Text(title), onTap: onTap);
  }

  Widget _buildGatewayStatusCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.router, color: Colors.blue),
                const SizedBox(width: 8),
                const Text(
                  'Gateway Status',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 16),
            if (gatewayStatus != null) ...[
              _buildStatusRow('Status', gatewayStatus!['status']),
              _buildStatusRow('Version', gatewayStatus!['version']),
              _buildStatusRow('Uptime', gatewayStatus!['uptime']),
              _buildStatusRow(
                'Active Connections',
                gatewayStatus!['active_connections'].toString(),
              ),
              _buildStatusRow(
                'Total Requests',
                gatewayStatus!['total_requests'].toString(),
              ),
            ] else ...[
              const CircularProgressIndicator(),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildPluginsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.extension, color: Colors.green),
                const SizedBox(width: 8),
                const Text(
                  'Plugins',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 16),
            ...plugins.map((plugin) => _buildPluginItem(plugin)),
          ],
        ),
      ),
    );
  }

  Widget _buildRoutesCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.route, color: Colors.orange),
                const SizedBox(width: 8),
                const Text(
                  'Routes',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 16),
            ...routes.map((route) => _buildRouteItem(route)),
          ],
        ),
      ),
    );
  }

  Widget _buildLogsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.list_alt, color: Colors.purple),
                const SizedBox(width: 8),
                const Text(
                  'Recent Logs',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Container(
              height: 300,
              child: ListView.builder(
                itemCount: logs.length,
                itemBuilder: (context, index) {
                  final log = logs[index];
                  return _buildLogItem(log);
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontWeight: FontWeight.w500)),
          Text(value),
        ],
      ),
    );
  }

  Widget _buildPluginItem(Map<String, dynamic> plugin) {
    return ListTile(
      title: Text(plugin['name']),
      subtitle: Text(plugin['type']),
      trailing: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: plugin['status'] == 'healthy' ? Colors.green : Colors.red,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Text(
          plugin['status'],
          style: const TextStyle(color: Colors.white, fontSize: 12),
        ),
      ),
    );
  }

  Widget _buildRouteItem(Map<String, dynamic> route) {
    return ListTile(
      title: Text(route['path']),
      subtitle: Text(route['destination']),
      trailing: Icon(
        route['active'] ? Icons.check_circle : Icons.cancel,
        color: route['active'] ? Colors.green : Colors.red,
      ),
    );
  }

  Widget _buildLogItem(Map<String, dynamic> log) {
    Color levelColor;
    switch (log['level']) {
      case 'error':
        levelColor = Colors.red;
        break;
      case 'warn':
        levelColor = Colors.orange;
        break;
      case 'info':
        levelColor = Colors.blue;
        break;
      default:
        levelColor = Colors.grey;
    }

    return ListTile(
      leading: Icon(Icons.circle, color: levelColor, size: 12),
      title: Text(log['message'], style: const TextStyle(fontSize: 14)),
      subtitle: Text(
        '${log['timestamp']} - ${log['level'].toUpperCase()}',
        style: const TextStyle(fontSize: 12),
      ),
    );
  }
}
