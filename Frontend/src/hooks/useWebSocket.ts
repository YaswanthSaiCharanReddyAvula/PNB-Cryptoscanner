import { useState, useEffect, useCallback, useRef } from 'react';

export type WSMessage = {
  type: 'status' | 'log' | 'data' | 'error' | 'metrics';
  stage?: number;
  status?: 'pending' | 'running' | 'completed' | 'failed' | 'update';
  message?: string;
  assets_count?: number;
  assets?: any[];
  data?: Record<string, any>;
};

export const useWebSocket = (scanId: string | null) => {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [status, setStatus] = useState<'connecting' | 'open' | 'closed'>('closed');
  const socketRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!scanId) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Using hardcoded localhost:8000 for now as per api.ts fallback
    const wsUrl = `${protocol}//localhost:8000/ws/scan/${scanId}`;
    
    setStatus('connecting');
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;

    socket.onopen = () => {
      setStatus('open');
      console.log('WebSocket connected');
    };

    socket.onmessage = (event) => {
      try {
        const message: WSMessage = JSON.parse(event.data);
        setMessages((prev) => [...prev, message]);
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
