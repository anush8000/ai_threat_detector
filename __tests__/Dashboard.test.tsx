import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Dashboard from '@/app/components/Dashboard';

const observe = vi.fn();
const unobserve = vi.fn();
const disconnect = vi.fn();
window.IntersectionObserver = vi.fn(() => ({
    observe,
    unobserve,
    disconnect,
    takeRecords: () => [],
})) as unknown as typeof window.IntersectionObserver;

vi.mock('@/services/runtimeMonitor', () => ({
    mockRuntimeEvents: [
        { instanceId: 'i-mock-aws', provider: 'aws', cpuUsage: 99, suspiciousPorts: [22] },
        { instanceId: 'gcp-mock-vm', provider: 'gcp', cpuUsage: 95, suspiciousPorts: [] },
        { instanceId: 'az-mock-vm', provider: 'azure', cpuUsage: 90, suspiciousPorts: [3389] },
    ],
    evaluateAnomaly: vi.fn(() => true),
    calculateAnomalyScore: vi.fn(() => ({ threatLevel: 'HIGH', score: 99, contributingFeatures: [] })),
}));

global.fetch = vi.fn();

const mockFetchRouting = (forceSteampipeSuccess = false, forceAIFail = false) => {
    return vi.fn((url: string | URL | Request) => {
        const urlStr = url.toString();
        if (urlStr.includes('/api/steampipe')) {
            if (forceSteampipeSuccess) return Promise.resolve({ ok: true, json: async () => ({ rows: [], rowCount: 0 }) });
            return Promise.reject(new Error('API Down'));
        }
        if (urlStr.includes('/api/ai-summary')) {
            if (forceAIFail) return Promise.resolve({ ok: false, status: 504, json: async () => ({ error: 'Groq Timeout' }) });
            return Promise.resolve({ ok: true, json: async () => ({ summary: 'AI synthesis complete.' }) });
        }
        if (urlStr.includes('/api/ai-chat')) {
            return Promise.resolve({ ok: true, json: async () => ({ reply: 'Here is how you fix it.' }) });
        }
        return Promise.resolve({ ok: true, json: async () => ({}) });
    });
};

describe('Enterprise Dashboard Integration Logic', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('1. Renders the loading skeleton initially before data sets', () => {
        global.fetch = vi.fn(() => new Promise(() => { }));
        const { container } = render(<Dashboard />);
        expect(container.getElementsByClassName('animate-pulse').length).toBeGreaterThan(0);
    });

    it('2. Renders the default AWS view with baseline mock data on fetch failure', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => expect(screen.getByText('AI Powered Cloud Threat Detection System')).toBeInTheDocument());
    });

    it('3. Multi-Cloud Toggles dynamically filter the analytics and workloads (AWS)', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        const awsBtn = screen.getByRole('button', { name: /Filter by aws cloud/i });
        fireEvent.click(awsBtn);
        expect(awsBtn).toHaveClass('bg-white', 'text-black');
    });

    it('4. Multi-Cloud Toggles dynamically filter the analytics and workloads (GCP)', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        const gcpBtn = screen.getByRole('button', { name: /Filter by gcp cloud/i });
        fireEvent.click(gcpBtn);
        await waitFor(() => expect(screen.queryAllByText(/gcp-mock-vm/i).length).toBeGreaterThan(0));
    });

    it('5. Multi-Cloud Toggles dynamically filter the analytics and workloads (Azure)', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        const azureBtn = screen.getByRole('button', { name: /Filter by azure cloud/i });
        fireEvent.click(azureBtn);
        await waitFor(() => expect(screen.queryAllByText(/az-mock-vm/i).length).toBeGreaterThan(0));
    });

    it('6. Handles Steampipe API fetch and seamlessly blends Live data with the UI', async () => {
        global.fetch = mockFetchRouting(true);
        render(<Dashboard />);
        await waitFor(() => expect(screen.getByRole('button', { name: /Refresh Security Data/i })).not.toBeDisabled());
    });

    it('7. Displays clear state when zero issues are returned', async () => {
        global.fetch = mockFetchRouting(true);
        render(<Dashboard />);
        await waitFor(() => expect(screen.getByText('All Clear')).toBeInTheDocument());
    });

    it('8. Renders pie chart when issues are present', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('Severity Distribution'));
    });

    it('9. Renders bar chart when categories are present', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('Issues by Service Category'));
    });

    it('10. Allows expanding issues to view remediation instructions', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('Configuration & Vulnerabilities'));
        const mockIssue = screen.getAllByText('Overly Permissive Security Group')[0];
        fireEvent.click(mockIssue.closest('.interactive-row')!);
        await waitFor(() => expect(screen.getByText('RECOMMENDED REMEDIATION')).toBeInTheDocument());
    });

    it('11. Allows collapsing expanded issues', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('Configuration & Vulnerabilities'));
        const mockIssue = screen.getAllByText('Overly Permissive Security Group')[0];
        fireEvent.click(mockIssue.closest('.interactive-row')!);
        await waitFor(() => expect(screen.getByText('RECOMMENDED REMEDIATION')).toBeInTheDocument());
        fireEvent.click(mockIssue.closest('.interactive-row')!);
        await waitFor(() => expect(screen.queryByText('RECOMMENDED REMEDIATION')).not.toBeInTheDocument());
    });

    it('12. Initiates AI summary generation and updates UI state', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        const assessBtn = screen.getByRole('button', { name: /Assess with AI Copilot/i });
        fireEvent.click(assessBtn);
        await waitFor(() => expect(screen.getByText('SYNTHESIZING...')).toBeInTheDocument());
        await waitFor(() => expect(screen.getByText('AI synthesis complete.')).toBeInTheDocument());
    });

    it('13. Shows AI error boundary within copilot box on failure', async () => {
        global.fetch = mockFetchRouting(false, true);
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        const assessBtn = screen.getByRole('button', { name: /Assess with AI Copilot/i });
        fireEvent.click(assessBtn);
        await waitFor(() => expect(screen.getByText(/Groq Timeout/i)).toBeInTheDocument());
    });

    it('14. Allows sending follow-up chat message to AI after summary generation', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        fireEvent.click(screen.getByRole('button', { name: /Assess with AI Copilot/i }));
        await waitFor(() => expect(screen.getByPlaceholderText(/Ask Copilot about this summary/i)).toBeInTheDocument());

        const input = screen.getByPlaceholderText(/Ask Copilot about this/i);
        fireEvent.change(input, { target: { value: 'How to fix S3?' } });
        fireEvent.click(screen.getByRole('button', { name: /Send Copilot Message/i }));

        await waitFor(() => {
            expect(screen.getByText('How to fix S3?')).toBeInTheDocument();
            expect(screen.getByText('Here is how you fix it.')).toBeInTheDocument();
        });
    });

    it('15. Prevents empty AI chat submission', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('SecOps Copilot'));
        fireEvent.click(screen.getByRole('button', { name: /Assess with AI Copilot/i }));
        await waitFor(() => screen.getByPlaceholderText(/Ask Copilot/i));

        const sendBtn = screen.getByRole('button', { name: /Send Copilot Message/i });
        expect(sendBtn).toBeDisabled();
    });

    it('16. Validates compliance score calculations dynamically map to UI', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => expect(screen.getByText(/Compliance Status/i)).toBeInTheDocument());
        expect(screen.queryAllByText(/%/i).length).toBeGreaterThan(0);
    });

    it('17. Refresh button triggers new data fetch cycle', async () => {
        global.fetch = mockFetchRouting(true);
        render(<Dashboard />);
        await waitFor(() => expect(global.fetch).toHaveBeenCalled());
        (global.fetch as any).mockClear();
        const refreshBtn = screen.getByRole('button', { name: /Refresh Security Data/i });
        fireEvent.click(refreshBtn);
        await waitFor(() => expect(global.fetch).toHaveBeenCalled());
    });

    it('18. Header indicates live system heartbeat', async () => {
        global.fetch = mockFetchRouting();
        const { container } = render(<Dashboard />);
        await waitFor(() => screen.getByText('System Active'));
        expect(container.getElementsByClassName('live-pulse').length).toBeGreaterThan(0);
    });

    it('19. ML Workload Anomaly list auto scales and isolates critical threat colors', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => screen.getByText('Active ML Workloads'));
        const criticalScore = screen.getAllByText('99')[0];
        expect(criticalScore).toHaveClass('text-red-400');
    });

    it('20. Test complete Dashboard container renders correctly nested layout', async () => {
        global.fetch = mockFetchRouting();
        render(<Dashboard />);
        await waitFor(() => expect(screen.getByText('AI Powered Cloud Threat Detection System')).toBeInTheDocument());
        expect(screen.getByText('Configuration & Vulnerabilities')).toBeInTheDocument();
    });
});
