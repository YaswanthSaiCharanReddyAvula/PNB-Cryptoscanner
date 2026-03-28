import { useState, useEffect, useCallback, useRef } from 'react';

/** Same host as REST API (Kali VM IP when VITE_API_BASE_URL points there). */
function getBackendWsOrigin(): string {
  const base =
    import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
  try {
    const u = new URL(base);
    const wsProto = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${wsProto}//${u.host}`;
  } catch {
    return 'ws://localhost:8000';
  }
}

export type WSMessage = {
  type: 'status' | 'log' | 'data' | 'error' | 'metrics';
  stage?: number | string;
  status?: 'pending' | 'running' | 'completed' | 'failed' | 'update';
  message?: string;
  assets_count?: number;
  assets?: any[];
  data?: Record<string, unknown>;
};

/** Normalize pipeline broadcasts (`type`) and DB-poll frames from `ws.py` (no `type`). */
function parseWsPayload(raw: unknown): WSMessage | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;

  if (typeof o.type === 'string') {
    return o as unknown as WSMessage;
  }

  if (typeof o.status === 'string') {
    const st = o.status as WSMessage['status'];
    const msg =
      typeof o.message === 'string'
        ? o.message
        : typeof o.stage === 'string'
          ? `${o.stage}…`
          : 'Scan update';
    return {
      type: 'status',
      status: st === 'running' || st === 'completed' || st === 'failed' || st === 'update' || st === 'pending' ? st : 'update',
      message: msg,
      stage: o.stage as string | number | undefined,
    };
  }

  return null;
}

export const useWebSocket = (scanId: string | null) => {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [status, setStatus] = useState<'connecting' | 'open' | 'closed'>('closed');
  const socketRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!scanId) return;

    const wsUrl = `${getBackendWsOrigin()}/ws/scan/${scanId}`;
    
    setStatus('connecting');
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;

    socket.onopen = () => {
      setStatus('open');
      console.log('WebSocket connected');
    };

    socket.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        const message = parseWsPayload(parsed);
        if (message) {
          setMessages((prev) => [...prev, message]);
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message', err);
      }
    };

    socket.onclose = () => {
      setStatus('closed');
      console.log('WebSocket disconnected');
    };

    socket.onerror = (error) => {
      console.error('WebSocket error:', error);
      setStatus('closed');
    };
  }, [scanId]);

  useEffect(() => {
    if (scanId) {
      connect();
    }
    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [scanId, connect]);

  const clearMessages = useCallback(() => {
    setMessages([]);
  }, []);

  return { messages, status, clearMessages };
};
