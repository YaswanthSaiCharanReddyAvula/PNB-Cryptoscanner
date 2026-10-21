import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '../hooks/useWebSocket';
import { LoginResponse } from '../services/types';

describe('Stage 2 Patches', () => {
  describe('WebSocket Fix', () => {
    let mockWebSocket: any;
    
    beforeEach(() => {
      mockWebSocket = {
        close: vi.fn(),
      };
      global.WebSocket = vi.fn(() => mockWebSocket) as any;
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should not push a synthetic failed status message upon socket close if scan is running', () => {
      const { result } = renderHook(() => useWebSocket('test-scan'));
      
      act(() => {
        if (mockWebSocket.onopen) mockWebSocket.onopen();
      });

      expect(result.current.status).toBe('open');

      // push a running status
      act(() => {
        if (mockWebSocket.onmessage) {
          mockWebSocket.onmessage({ data: JSON.stringify({ type: 'status', status: 'running' }) });
        }
      });
      
      expect(result.current.messages[0]?.status).toBe('running');

      // trigger connection drop
      act(() => {
        if (mockWebSocket.onclose) mockWebSocket.onclose();
      });

      // Assert status closed
      expect(result.current.status).toBe('closed');
      
      // Assert no synthetic 'failed' message was injected
      expect(result.current.messages.length).toBe(1);
      expect(result.current.messages[result.current.messages.length - 1].status).not.toBe('failed');
    });
  });

  describe('LoginResponse Auth Type', () => {
    it('should compile correctly with valid OTP login response payload', () => {
      const payload: LoginResponse = {
        requires_otp: true,
        email: 'admin@example.com',
        message: 'OTP Sent'
      };
      expect(payload.requires_otp).toBe(true);
    });

    it('should compile correctly with standard token login response payload', () => {
      const payload: LoginResponse = {
        access_token: 'abc',
        token_type: 'bearer',
        user: { email: 'a@a.com', role: 'admin' }
      };
      if (!('requires_otp' in payload)) {
        expect(payload.access_token).toBe('abc');
      }
    });
  });
});
