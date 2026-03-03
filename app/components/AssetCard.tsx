'use client';

interface Asset {
  name: string;
  type: string;
  status: 'active' | 'inactive' | 'pending';
  count?: number;
  region?: string;
}

export default function AssetCard({ asset }: { asset: Asset }) {
  const statusColors = {
    active:   'bg-green-100  text-green-800',
    inactive: 'bg-gray-100   text-gray-800',
    pending:  'bg-yellow-100 text-yellow-800',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6 border border-gray-200 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">{asset.name}</h3>
          <p className="text-sm text-gray-500 mt-1">{asset.type}</p>
        </div>
        <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusColors[asset.status]}`}>
          {asset.status}
        </span>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        {asset.count !== undefined && (
          <div>
            <p className="text-xs text-gray-800 uppercase tracking-wide">Count</p>
            <p className="text-2xl font-bold text-gray-900 mt-1">{asset.count}</p>
          </div>
        )}
        {asset.region && (
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wide">Region</p>
            <p className="text-sm font-medium text-gray-900 mt-1">{asset.region}</p>
          </div>
        )}
      </div>
    </div>
  );
}