import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, it, expect, vi } from 'vitest';
import { App } from './App';

// Mock global fetch for react-query calls
global.fetch = vi.fn().mockImplementation((url: string) => {
  if (url.endsWith('/ready')) {
    return Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          status: 'ready',
          models_loaded: true,
          model_mode: 'trained',
          bundle_dir: 'artifacts/model_cards/current',
        }),
    });
  }
  if (url.endsWith('/health')) {
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ status: 'healthy' }),
    });
  }
  if (url.includes('/sessions')) {
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve([]),
    });
  }
  if (url.includes('/incidents')) {
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve([]),
    });
  }
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({}),
  });
});

describe('App Component', () => {
  it('renders header, navigation tabs, and system invariants', () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    );

    expect(screen.getByText(/Agentic Traffic Threat Triage/i)).toBeDefined();
    expect(screen.getAllByText(/Session Explorer/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Benchmark Evals/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Architecture Invariants/i)).toBeDefined();
  });
});
