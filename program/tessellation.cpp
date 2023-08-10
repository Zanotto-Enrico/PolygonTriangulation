#include "headers.hpp"


// Calculate arc length between two indices in a cyclic array
int arc_length(int i, int j, int N) {
    return std::min(std::abs(i - j), N - std::abs(i - j));
}


std::vector<std::vector<Coord>> subdividePolygon(const std::vector<Coord>& perimeter, const std::vector<Edge>& diagonals) {
    int numVertices = static_cast<int>(perimeter.size());
    LessPredicate lessPredicate(numVertices);

    std::vector<Edge> sortedDiagonals = diagonals;
    std::sort(sortedDiagonals.begin(), sortedDiagonals.end(), lessPredicate);

    std::vector<std::vector<Coord>> subPolygons;
    std::vector<bool> diagonalUsed(perimeter.size(), false);
    
    std::vector<Coord> startingVertices;
    startingVertices.push_back(perimeter[0]);

    while (!startingVertices.empty()) {

        std::vector<Coord> subPolygon;
        Coord current = *(startingVertices.end()-1);
        startingVertices.pop_back();

        int end = current.index;
        bool diagonalTaken = true;
        do {
            subPolygon.push_back(current);
            if(!diagonalTaken)
                for (const Edge& diagonal : diagonals) {
                    if (diagonal.start.index == current.index) {
                        if(!diagonalUsed[current.index])
                            startingVertices.push_back(current);
                        diagonalUsed[current.index] = diagonalUsed[diagonal.end.index] = true;
                        current = diagonal.end;
                        diagonalTaken = true;
                        break;
                    } else if (diagonal.end.index == current.index ) {
                        if(!diagonalUsed[current.index])
                            startingVertices.push_back(current);
                        diagonalUsed[current.index] = diagonalUsed[diagonal.start.index] = true;
                        current = diagonal.start;
                        diagonalTaken = true;
                        break;
                    }
                }
            else
                diagonalTaken = false;
            if(!diagonalTaken)
                current = perimeter[(current.index+1)%perimeter.size()];
                
            
        } while (current.index != end);

        subPolygons.push_back(subPolygon);
    }


    return subPolygons;
}



// finds the first edge over a given point
const Edge* findUpperBound(double y,double x, std::set<Edge> bounds)
{
    std::set<Edge>::iterator it = bounds.end();    // can be improved
    if (it != bounds.begin()) {
        --it;  // Move to the previous edge
        if (y < it->start.y + ((it->end.y - it->start.y) / (it->end.x - it->start.x)) * (x - it->start.x)) {
            return &(*it);
        }
    }

    return nullptr;  // Return a default Edge if not found
}

/*
    sweep line algorithm to partition non monoton polygons in monotone polygons
*/
std::vector<std::vector<Coord>> partitionPolygonIntoMonotone(std::vector<Coord>& polygon)
{
    for (size_t i = 0; i < polygon.size(); ++i)
    {
        polygon[i].index = i;
    }
    int vertices_num = polygon.size();
    // Step 2: Create the event queue and initialize it with vertex and edge events.
    std::vector<Coord> eventQueue = polygon;
    std::sort(eventQueue.begin(), eventQueue.end());

    // Step 3: Initialize the status data structure (e.g., a binary search tree).
    std::vector<Edge> newEdges;

    // Sweep line partitions boundaries
    std::set<Edge> activeEdges;

    // true if previous vertex was a merge vertex
    bool mergeFound = false;

    for (const Coord& event : eventQueue)
    {

        Coord prev = polygon[(event.index+vertices_num-1)%vertices_num];
        Coord next = polygon[(event.index+1)%vertices_num];

        // Determine whether this is a merge vertex, split vertex, or regular vertex.

        bool isMerge = false, isEnd = false, isSplit = false, isStart = false;
        if(prev.x < event.x && next.x < event.x)
        {
            if(prev.y > event.y)
                isMerge = true;
            else
                isEnd = true;
        }
        if(prev.x > event.x && next.x > event.x)
        {
            if(prev.y > event.y)
                isStart = true;
            else
                isSplit = true;
        }
        bool isRegularUpper = !isMerge && !isEnd && !isSplit && !isStart && next.x <= event.x && event.x <= prev.x;
        bool isRegularLower = !isMerge && !isEnd && !isSplit && !isStart && next.x >= event.x && event.x >= prev.x;

        if (isMerge) // Handle merge vertices 
        {
            std::cout << "Merge    " << event.x << "," << event.y << std::endl;
            activeEdges.erase(Edge(prev,event));
            activeEdges.erase(Edge(event,next));
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                    newEdges.push_back({{event.x,event.y,event.z, event.index},{e->helper->x,e->helper->y,e->helper->z, e->helper->index}}); 
            }
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(e)
                e->helper->x = event.x; e->helper->y = event.y; e->helper->z = event.z; e->helper->index = event.index;
            mergeFound = true;
        }
        if (isSplit) // Handle split vertices 
        {

            std::cout << "Split    " << event.x << "," << event.y << std::endl;

            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(e)
                newEdges.push_back({{event.x,event.y,event.z,event.index},{e->helper->x,e->helper->y,e->helper->z, e->helper->index}}); 
            
            activeEdges.insert(Edge(prev,event,event));
            activeEdges.insert(Edge(event,next,event));
            mergeFound = false;
        }
        if(isStart) 
        {
            std::cout << "Start    " << event.x << "," << event.y << std::endl;
            activeEdges.insert(Edge(prev,event,event));
            activeEdges.insert(Edge(next,event,event));
        }
        if(isEnd) 
        {
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                   newEdges.push_back({{event.x,event.y,event.z, event.index},{e->helper->x,e->helper->y,e->helper->z,e->helper->index}}); 
                mergeFound = false;
            }
            std::cout << "End      " << event.x << "," << event.y << std::endl;
            activeEdges.erase(Edge(prev,event));
            activeEdges.erase(Edge(event,next));
        }
        if (isRegularUpper) 
        {
            std::cout << "Upper    " << event.x << "," << event.y << std::endl;
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                   newEdges.push_back({{event.x,event.y,event.z, event.index},{e->helper->x,e->helper->y,e->helper->z,e->helper->index}}); 
                mergeFound = false;
            }
            activeEdges.erase(Edge(event,next));
            activeEdges.insert(Edge(event,prev,event));
        }
        if (isRegularLower) 
        {
            if(mergeFound)
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(e)
                    newEdges.push_back({{event.x,event.y,event.z,event.index},{e->helper->x,e->helper->y,e->helper->z,e->helper->index}}); 
                mergeFound = false;
            }
            std::cout << "Lower    " << event.x << "," << event.y << std::endl;
            activeEdges.erase(Edge(event,prev));
            activeEdges.insert(Edge(event,next,event));
        }
    }

    for(Edge e : newEdges)
    {
        std::cout << "Added edge: (" << e.start.x << ";" << e.start.y << ")   (" << e.end.x << ";" << e.end.y << ")\n";
    }
    return subdividePolygon(polygon,newEdges);
}

std::vector<Triangle> tessellateMonotonePolygon(const std::vector<Coord>& polygon) {
    std::vector<Triangle> triangles;

    if (polygon.size() < 3) {
        return triangles; // Not enough vertices to triangulate
    }

    std::vector<Coord> upperChain, lowerChain;
    size_t lastReflex = 0;

    for (size_t i = 0; i < polygon.size(); ++i) {
        if (polygon[i].index == 0) {
            lastReflex = i;
        }
    }

    for (size_t i = 0; i < polygon.size(); ++i) {
        if (polygon[i].index == lastReflex) {
            // Start of the reflex chain
            if (i == 0) {
                upperChain.push_back(polygon[i]);
            } else if (i == polygon.size() - 1) {
                lowerChain.push_back(polygon[i]);
            } else {
                if (polygon[i - 1].x < polygon[i + 1].x) {
                    upperChain.push_back(polygon[i]);
                } else {
                    lowerChain.push_back(polygon[i]);
                }
            }
        } else {
            // Non-reflex vertex
            if (upperChain.empty() || upperChain.back().x <= polygon[i].x) {
                upperChain.push_back(polygon[i]);
            } else {
                while (upperChain.size() > 1 && upperChain.back().x > polygon[i].x) {
                    triangles.push_back({upperChain[upperChain.size() - 2], upperChain.back(), polygon[i]});
                    upperChain.pop_back();
                }
                lowerChain.push_back(polygon[i]);
            }
        }
    }

    // Triangulate the remaining vertices
    for (size_t i = 1; i < upperChain.size() - 1; ++i) {
        triangles.push_back({upperChain[0], upperChain[i], upperChain[i + 1]});
    }

    for (size_t i = 1; i < lowerChain.size() - 1; ++i) {
        triangles.push_back({lowerChain[0], lowerChain[i], lowerChain[i + 1]});
    }

    return triangles;
}
