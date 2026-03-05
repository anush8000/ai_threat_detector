import '@testing-library/jest-dom';
import React from 'react';
import { vi } from 'vitest';

// Mock the Recharts ResponsiveContainer to have a valid width/height during jsdom tests
vi.mock('recharts', async () => {
    const OriginalRechartsModule = await vi.importActual('recharts');
    return {
        ...(OriginalRechartsModule as object),
        ResponsiveContainer: ({ children }: { children: React.ReactNode }) =>
            React.createElement('div', { className: 'responsive-container-mock', style: { width: 800, height: 800 } }, children)
    };
});
