import { useState, useEffect, useRef } from 'react'

interface Packet {
  timestamp: string
  src_ip: string
  dst_ip: string
  protocol: string
  src_port: number
  dst_port: number
  size: number
  status: string
  id: number
  threats: string[]
}

interface Stats {
  total: number
  normal: number
  suspicious: number
  blocked: number
}

function App() {
  const [stats, setStats] = useState<Stats>({ total: 0, normal: 0, suspicious: 0, blocked: 0 })
  const [packets, setPackets] = useState<Packet[]>([])
  const [blockedIps, setBlockedIps] = useState<string[]>([])
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null)
  const [manualIp, setManualIp] = useState('')
  const [blockTarget, setBlockTarget] = useState<'src' | 'dst'>('src')
  const [isRunning, setIsRunning] = useState(false)
  const [initLoaded, setInitLoaded] = useState(false)

  // Ticker Queue System
  const packetQueue = useRef<Packet[]>([])
  const lastFetchedId = useRef<number>(0)

  // 1. Fetch Data (Producer)
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/stats')
        const data = await response.json()
        setStats(data.stats)

        if (data.packets.length > 0) {
          // Filter for TRULY new packets only
          const incoming = data.packets;

          // Re-fetching logic:
          const sortedNew = incoming.sort((a: Packet, b: Packet) => a.id - b.id);
          const uniqueNew = sortedNew.filter((p: Packet) => p.id > lastFetchedId.current);

          if (uniqueNew.length > 0) {
            lastFetchedId.current = uniqueNew[uniqueNew.length - 1].id;
            packetQueue.current = [...packetQueue.current, ...uniqueNew];
          }
        }
        setBlockedIps(data.blocked_ips)
      } catch (error) {
        // console.error("Failed to fetch stats")
      }
    }

    const interval = setInterval(fetchStats, isRunning ? 1000 : 3000)
    return () => clearInterval(interval)
  }, [isRunning])

  // 2. Ticker Animation (Consumer)
  useEffect(() => {
    // Request notification permission on start
    if ("Notification" in window && Notification.permission !== "granted") {
      Notification.requestPermission();
    }
  }, []);

  useEffect(() => {
    if (!isRunning) return;

    const ticker = setInterval(() => {
      if (packetQueue.current.length > 0) {
        // Take 1 packet from queue
        // We use a Set to ensure NO duplicates in the display list based o ID
        setPackets(prev => {
          // If queue has duplicates from repeated fetches, we can filter here
          // But let's just pop one
          if (packetQueue.current.length === 0) return prev;

          const nextPacket = packetQueue.current.shift(); // FIFO
          if (!nextPacket) return prev;

          // Check if we already have this ID to avoid duplication from repeated API polls
          if (prev.some(p => p.id === nextPacket.id)) {
            return prev;
          }

          // NOTIFICATION LOGIC
          if (nextPacket.threats && nextPacket.threats.length > 0) {
            if (Notification.permission === "granted") {
              // Simple debounce: check if we notified recently? 
              // For now, let's notify for every unique suspicious packet found in the *ticker*
              // To avoid spam, maybe we can rely on system grouping or just let it be alert-heavy as requested.
              new Notification(`⚠️ Suspicious Activity Detected!`, {
                body: `Source: ${nextPacket.src_ip}\nThreat: ${nextPacket.threats.join(', ')}`,
                icon: '/shield-warning.png' // Optional icon if available
              });
            }
          }

          // Add to top, keep max 50 visible
          const newList = [nextPacket, ...prev];
          return newList.slice(0, 50);
        });
      }
    }, 150); // Tick every 150ms = ~6 packets per second. Smooth.

    return () => clearInterval(ticker);
  }, [isRunning]);

  const toggleMonitoring = async () => {
    const endpoint = isRunning ? 'stop' : 'start'
    try {
      await fetch(`http://localhost:5000/api/${endpoint}`, { method: 'POST' })
      setIsRunning(!isRunning)
      if (!initLoaded) setInitLoaded(true)
    } catch (error) {
      console.error(`Failed to ${endpoint}`, error)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const blockIp = async (ip: string) => {
    try {
      await fetch('http://localhost:5000/api/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      })
      setManualIp('')
    } catch (error) {
      console.error("Failed to block IP", error)
    }
  }

  const unblockIp = async (ip: string) => {
    try {
      await fetch('http://localhost:5000/api/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      })
    } catch (error) {
      console.error("Failed to unblock IP", error)
    }
  }

  const handlePacketSelect = (packet: Packet) => {
    setSelectedPacket(packet)
    const ip = blockTarget === 'src' ? packet.src_ip : packet.dst_ip
    setManualIp(ip)
  }

  return (
    <div className="flex h-screen text-text-primary font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-72 glass border-r border-white/5 flex flex-col relative z-20">
        <div className="p-6 border-b border-white/5">
          <h1 className="text-2xl font-bold bg-gradient-to-r from-accent to-blue-400 bg-clip-text text-transparent">TRAFFIC A.I.</h1>
          <p className="text-[10px] text-text-secondary uppercase tracking-[0.2em] mt-1 opacity-70">Security Monitor</p>
        </div>

        <div className="p-6 space-y-4 flex-1 overflow-y-auto">
          <div className="grid grid-cols-2 gap-3">
            <StatCard label="Total" value={stats.total} color="text-info" />
            <StatCard label="Normal" value={stats.normal} color="text-success" />
            <StatCard label="Suspicious" value={stats.suspicious} color="text-warning" />
            <StatCard label="Blocked" value={stats.blocked} color="text-danger" />
          </div>

          <div className="mt-8">
            <h3 className="text-xs font-bold text-text-secondary mb-4 uppercase tracking-widest pl-1">Active Blocks</h3>
            <div className="glass-card rounded-lg p-2 h-64 overflow-y-auto text-sm font-mono scrollbar-hide">
              {blockedIps.length === 0 && (
                <div className="h-full flex items-center justify-center text-text-secondary opacity-30 text-xs">
                  NO BLOCKED IPs
                </div>
              )}
              {blockedIps.map(ip => (
                <div key={ip} className="flex justify-between items-center mb-2 last:mb-0 p-2 rounded hover:bg-white/5 group transition-all animate-fade-in border border-transparent hover:border-red-500/20">
                  <span className="text-red-400">{ip}</span>
                  <button
                    onClick={() => unblockIp(ip)}
                    className="text-text-secondary hover:text-white opacity-0 group-hover:opacity-100 transition-all transform hover:scale-110"
                  >
                    ⨯
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="p-6 mt-auto border-t border-white/5">
          <button
            onClick={toggleMonitoring}
            className={`w-full py-4 rounded-xl font-bold text-sm uppercase tracking-wider transition-all duration-300 transform hover:scale-[1.02] shadow-lg ${isRunning
              ? 'bg-red-500/10 text-red-500 border border-red-500/50 hover:bg-red-500/20'
              : 'bg-accent/10 text-accent border border-accent/50 hover:bg-accent/20'
              }`}
          >
            {isRunning ? 'Stop Monitoring' : 'Start Monitoring'}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 relative z-10">
        {/* Header Control Bar */}
        <header className="glass border-b border-white/5 p-4 flex items-center justify-between shadow-2xl z-30">
          <div className="flex items-center space-x-6">
            {/* Target Selector */}
            <div className="flex bg-black/20 rounded-lg p-1 border border-white/5">
              <button
                className={`px-4 py-1.5 rounded-md text-xs font-bold uppercase transition-all ${blockTarget === 'src' ? 'bg-accent text-[#0b132b] shadow-lg' : 'text-text-secondary hover:text-white'}`}
                onClick={() => setBlockTarget('src')}
              >
                Source IP
              </button>
              <button
                className={`px-4 py-1.5 rounded-md text-xs font-bold uppercase transition-all ${blockTarget === 'dst' ? 'bg-accent text-[#0b132b] shadow-lg' : 'text-text-secondary hover:text-white'}`}
                onClick={() => setBlockTarget('dst')}
              >
                Dest IP
              </button>
            </div>

            {/* Manual Input */}
            <div className="flex items-center group relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <span className="text-gray-500 text-xs">IP</span>
              </div>
              <input
                type="text"
                value={manualIp}
                onChange={(e) => setManualIp(e.target.value)}
                placeholder="0.0.0.0"
                className="bg-black/20 border border-white/10 rounded-l-lg pl-8 pr-4 py-2 text-sm text-white focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent w-48 font-mono transition-all"
              />
              <button
                onClick={() => manualIp && blockIp(manualIp)}
                className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-r-lg text-xs font-bold uppercase tracking-wider transition-all border-l border-white/10"
              >
                Block
              </button>
            </div>
          </div>

          {/* Selected Packet Indicator */}
          <div className={`flex items-center space-x-4 transition-all duration-300 ${selectedPacket ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'}`}>
            {selectedPacket && (
              <>
                <div className="flex flex-col items-end">
                  <span className="text-[10px] text-text-secondary uppercase tracking-wider">Selected Target</span>
                  <span className="font-mono text-accent text-lg leading-none">{blockTarget === 'src' ? selectedPacket.src_ip : selectedPacket.dst_ip}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(blockTarget === 'src' ? selectedPacket.src_ip : selectedPacket.dst_ip)}
                  className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-text-secondary hover:text-white transition-colors border border-white/5"
                  title="Copy IP to Clipboard"
                >
                  📋
                </button>
              </>
            )}
          </div>
        </header>

        {/* Hero / Table */}
        <div className="flex-1 overflow-hidden relative bg-[#0b132b]/50">
          {!initLoaded && !isRunning ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center z-0">
              <div className="w-24 h-24 rounded-full bg-accent/10 flex items-center justify-center mb-6 animate-pulse">
                <span className="text-4xl">🛡️</span>
              </div>
              <h2 className="text-3xl font-bold text-white mb-2">Ready to Monitor</h2>
              <p className="text-text-secondary max-w-md">Initialize the network analysis engine to start CAPTURING traffic packets.</p>
            </div>
          ) : (
            <div className="absolute inset-0 overflow-auto p-4 z-10">
              <table className="w-full text-left text-sm border-separate border-spacing-y-1">
                <thead className="sticky top-0 z-20">
                  <tr>
                    {['Time', 'Source', 'Destination', 'Proto', 'Port', 'Size', 'Status'].map(h => (
                      <th key={h} className="bg-[#0b132b]/95 backdrop-blur-sm p-4 text-xs font-bold text-text-secondary uppercase tracking-wider first:rounded-l-lg last:rounded-r-lg shadow-sm">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="pb-4">
                  {packets.map((packet) => (
                    <tr
                      key={packet.id}
                      onClick={() => handlePacketSelect(packet)}
                      className={`
                                        group cursor-pointer transition-all duration-200 animate-fade-in
                                        hover:scale-[1.002] hover:shadow-lg
                                        ${selectedPacket?.id === packet.id ? 'bg-accent/10 border-accent/30' : 'bg-[#16213e]/40 border-transparent hover:bg-[#16213e]/80'}
                                    `}
                    >
                      <td className="p-4 rounded-l-lg border-y border-l border-inherit font-mono text-text-secondary/70">{packet.timestamp}</td>
                      <td className="p-4 border-y border-inherit font-mono text-blue-400 group-hover:text-blue-300">{packet.src_ip}</td>
                      <td className="p-4 border-y border-inherit font-mono text-purple-400 group-hover:text-purple-300">{packet.dst_ip}</td>
                      <td className="p-4 border-y border-inherit font-bold text-white/80">{packet.protocol}</td>
                      <td className="p-4 border-y border-inherit text-text-secondary">{packet.dst_port}</td>
                      <td className="p-4 border-y border-inherit text-text-secondary">{packet.size} <span className="text-[10px] opacity-50">B</span></td>
                      <td className="p-4 rounded-r-lg border-y border-r border-inherit">
                        <StatusBadge status={packet.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string, value: number, color: string }) {
  return (
    <div className="glass-card rounded-xl p-4 flex flex-col justify-center items-center text-center hover:bg-white/5 transition-colors">
      <span className="text-[10px] font-bold text-text-secondary uppercase tracking-wider mb-1 opacity-70">{label}</span>
      <span className={`text-2xl font-bold ${color} drop-shadow-sm`}>{value.toLocaleString()}</span>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const getStyle = () => {
    switch (status) {
      case 'BLOCKED': return 'bg-red-500/10 text-red-500 border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
      case 'SUSPICIOUS': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20 shadow-[0_0_10px_rgba(234,179,8,0.1)]'
      default: return 'bg-green-500/10 text-green-500 border-green-500/20'
    }
  }
  return (
    <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold border tracking-wider uppercase ${getStyle()}`}>
      {status}
    </span>
  )
}

export default App
