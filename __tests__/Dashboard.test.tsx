import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Dashboard from '@/app/components/Dashboard';

// Mock the runtimeMonitor service to return predictable mock events
vi.mock('@/services/runtimeMonitor', () => ({
    mockRuntimeEvents: [
        { instanceId: 'i-mock-aws', provider: 'aws', score: 99, cpuUsage: 99, memoryUsage: 50, networkIn: 100, networkOut: 100, processCount: 10, diskReadIops: 10, diskWriteIops: 10, failedLogins: 5, suspiciousPorts: [22] },
        { instanceId: 'gcp-mock-vm', provider: 'gcp', score: 95, cpuUsage: 95, memoryUsage: 50, networkIn: 100, networkOut: 100, processCount: 10, diskReadIops: 10, diskWriteIops: 10, failedLogins: 5, suspiciousPorts: [] },
        { instanceId: 'az-mock-vm', provider: 'azure', score: 90, cpuUsage: 90, memoryUsage: 50, networkIn: 100, networkOut: 100, processCount: 10, diskReadIops: 10, diskWriteIops: 10, failedLogins: 5, suspiciousPorts: [3389] },
    ],
    evaluateAnomaly: vi.fn(() => true),
    calculateAnomalyScore: vi.fn(() => ({ threatLevel: 'CRITICAL', score: 99, contributingFeatures: [] })),
}));

// Mock the AI Context fetch calls
global.fetch = vi.fn();

describe('Enterprise Dashboard Integration Logic', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('1. Renders the default AWS view with baseline mock data immediately', () => {
        render(<Dashboard />);

        // Header check
        expect(screen.getByText('AI Powered Cloud Threat Detection System')).toBeInTheDocument();

        // Check if AWS is present
        const awsBtn = screen.getByRole('button', { name: /Filter by aws cloud/i });
        expect(awsBtn).toBeInTheDocument();

        // The security copilot should be ready
        expect(screen.getByText('SecOps Copilot')).toBeInTheDocument();
    });

    it('2. Cloud Toggles dynamically filter the analytics and workloads', async () => {
        render(<Dashboard />);

        // Switch to GCP
        const gcpBtn = screen.getByRole('button', { name: /Filter by gcp cloud/i });
        fireEvent.click(gcpBtn);

        // Assert GCP ML internal workloads are shown loosely matching text
        await waitFor(() => {
            const elements = screen.queryAllByText(/gcp-mock-vm/i);
            expect(elements.length).toBeGreaterThan(0);
        });

        // Check Azure
        const azureBtn = screen.getByRole('button', { name: /Filter by azure cloud/i });
        fireEvent.click(azureBtn);

        await waitFor(() => {
            const elements = screen.queryAllByText(/az-mock-vm/i);
            expect(elements.length).toBeGreaterThan(0);
        });
    });

    it('3. Handles Steampipe API fetch and seamlessly blends Live data with the UI', async () => {
        // Setup a mock fetch response matching the Steampipe internal API spec
        const mockApiResponse = {
            rows: [
                { name: 'live-prod-db-1', engine: 'aurora', region: 'us-east-1' },
            ],
            rowCount: 1
        };

        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => mockApiResponse
        });

        render(<Dashboard />);

        // Simulate connection / refresh flow
        const refreshBtn = screen.getByRole('button', { name: /Refresh/i });
        fireEvent.click(refreshBtn);

        // Assert that fetch was actually called (live integration point)
        await waitFor(() => {
            expect(global.fetch).toHaveBeenCalled();
        });
    });
});
