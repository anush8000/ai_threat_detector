export function DashboardSkeleton() {
    return (
        <div className="flex flex-col min-h-screen bg-[#000000]">
            {/* HEADER SKELETON */}
            <header className="h-[64px] bg-black/60 border-b border-white/5 flex items-center px-8">
                <div className="w-8 h-8 rounded-lg bg-white/10 animate-pulse mr-4" />
                <div className="h-5 w-64 bg-white/10 rounded-md animate-pulse" />
                <div className="ml-auto h-8 w-32 bg-white/10 rounded-full animate-pulse" />
            </header>

            <main className="py-8 px-7 max-w-[1600px] mx-auto w-full flex flex-col gap-8">
                {/* STAT CARDS SKELETON */}
                <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {[1, 2, 3, 4].map((i) => (
                        <div key={i} className="surface-card p-6 h-32 flex flex-col justify-between">
                            <div className="h-3 w-24 bg-white/10 rounded animate-pulse" />
                            <div className="h-12 w-20 bg-white/5 rounded animate-pulse" />
                            <div className="h-2 w-32 bg-white/5 rounded animate-pulse" />
                        </div>
                    ))}
                </section>

                {/* MAIN ROW SKELETON */}
                <section className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-4">
                    {/* Issue list skeleton */}
                    <div className="surface-card flex flex-col h-[750px]">
                        <div className="p-5 px-6 border-b border-white/5 flex justify-between">
                            <div className="h-5 w-48 bg-white/10 rounded animate-pulse" />
                            <div className="h-5 w-16 bg-white/10 rounded-full animate-pulse" />
                        </div>
                        <div className="p-4 flex flex-col gap-3">
                            {[1, 2, 3, 4, 5, 6].map((i) => (
                                <div key={i} className="flex gap-4 p-3 rounded-lg bg-white/[0.02]">
                                    <div className="w-16 h-6 rounded-full bg-white/5 animate-pulse" />
                                    <div className="flex-1 flex flex-col gap-2">
                                        <div className="h-4 w-1/3 bg-white/10 rounded animate-pulse" />
                                        <div className="h-3 w-1/2 bg-white/5 rounded animate-pulse" />
                                        <div className="h-3 w-3/4 bg-white/5 rounded animate-pulse" />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Right column skeleton */}
                    <div className="flex flex-col gap-4 h-[750px]">
                        <div className="surface-card h-[350px] p-5 flex flex-col">
                            <div className="h-5 w-32 bg-white/10 rounded animate-pulse mb-6" />
                            <div className="flex-1 flex flex-col gap-3">
                                <div className="h-16 w-full bg-white/5 rounded-xl animate-pulse" />
                                <div className="h-16 w-3/4 bg-white/5 rounded-xl animate-pulse ml-auto" />
                            </div>
                        </div>
                        <div className="surface-card flex-1 p-5">
                            <div className="h-5 w-40 bg-white/10 rounded animate-pulse mb-6" />
                            <div className="flex flex-col gap-4">
                                {[1, 2, 3].map((i) => (
                                    <div key={i} className="h-12 w-full bg-white/5 rounded animate-pulse" />
                                ))}
                            </div>
                        </div>
                    </div>
                </section>
            </main>
        </div>
    );
}
