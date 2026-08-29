"""Reachability analysis module."""

def rank_by_reachability(
    functions: list[str],
    call_graph: dict[str, list[str]],
    entrypoints: list[str] = None,
) -> list[tuple[str, int]]:
    """
    Rank functions by shortest distance from an entrypoint (which typically handles untrusted input).

    Args:
        functions: List of functions to rank.
        call_graph: A simple call graph represented as a dictionary where keys are caller
                    function names and values are lists of callee function names.
        entrypoints: List of entrypoint functions (e.g., "main").

    Returns:
        List of tuples (function_name, distance), sorted by distance (ascending).
    """
    # Initialize distances
    if entrypoints is None:
        entrypoints = ["main"]
    all_nodes = set(functions + list(call_graph.keys()) + entrypoints)
    for callees in call_graph.values():
        all_nodes.update(callees)
    distances = {func: float('inf') for func in all_nodes}

    # Queue for BFS: (current_node, distance)
    queue = [(ep, 0) for ep in entrypoints]

    for ep in entrypoints:
        distances[ep] = 0

    while queue:
        current, dist = queue.pop(0)

        for neighbor in call_graph.get(current, []):
            if distances[neighbor] > dist + 1:
                distances[neighbor] = dist + 1
                queue.append((neighbor, dist + 1))

    # Filter for requested functions and sort
    results = []
    for func in functions:
        dist = distances.get(func, float('inf'))
        results.append((func, dist))

    return sorted(results, key=lambda x: x[1])
