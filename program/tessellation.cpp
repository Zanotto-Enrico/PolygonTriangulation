#include "headers.hpp"


// Calculate arc length between two indices in a cyclic array
int arc_length(int i, int j, int N) {
    return std::min(std::abs(i - j), N - std::abs(i - j));
}


// finds the first edge over a given point
const Edge* findUpperBound(double y,double x, std::set<Edge> &bounds)
{
    std::set<Edge>::iterator it = bounds.begin();    // can be improved
    while (it != bounds.end()) {
        if (y < it->start.y + ((it->end.y - it->start.y) / (it->end.x - it->start.x)) * (x - it->start.x)) {
            return &(*it);
        }
        ++it;
    }

    return nullptr;  // Return a default Edge if not found
}

vertexType getVertexType(const Coord &vertex, const Coord &next, const Coord &prev )
{
    if(prev.x < vertex.x && next.x < vertex.x)
        if(prev.y > vertex.y)   return MERGE;
        else                    return END;
    
    if(prev.x > vertex.x && next.x > vertex.x)
        if(prev.y > vertex.y)   return START;
        else                    return SPLIT;

    if( next.x <= vertex.x && vertex.x <= prev.x)   return REGULAR_UPPER;
    if( next.x >= vertex.x && vertex.x >= prev.x)   return REGULAR_LOWER;
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
    // Create the event queue and initialize it with vertex and edge events.
    std::vector<Coord> eventQueue = polygon;
    std::sort(eventQueue.begin(), eventQueue.end());

    // Sweep line partitions boundaries
    std::set<Edge> activeEdges;

    // true if previous vertex was a merge vertex
    bool mergeFound = false;
    int indexOfMergeMonotone;

    // vecotor of all monotone polygons found devided in upper and lower chains
    std::vector<std::pair<std::vector<Coord>,std::vector<Coord>>> monotones;

    for (const Coord& event : eventQueue)
    {

        Coord prev = polygon[(event.index+vertices_num-1)%vertices_num];
        Coord next = polygon[(event.index+1)%vertices_num];

        // Determine whether this is a merge vertex, split vertex, or regular vertex.
        vertexType type = getVertexType(event, next, prev);

        if (type == MERGE) 
        {
            std::cout << "Merge    " << event.x << "," << event.y << std::endl;
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(mergeFound)
            {
                monotones[indexOfMergeMonotone].first.push_back(event);
            }
            if(e)
                e->helper->x = event.x; e->helper->y = event.y; e->helper->z = event.z; e->helper->index = event.index;
            
            monotones[*e->monotonePolygonIndex].second.push_back(event);
            indexOfMergeMonotone = *activeEdges.find(Edge(event,next))->monotonePolygonIndex;
            monotones[indexOfMergeMonotone].first.push_back(event);
            activeEdges.erase(Edge(event,next));
            mergeFound = true;
        }
        else if (type == SPLIT) 
        {

            std::cout << "Split    " << event.x << "," << event.y << std::endl;
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(!mergeFound)
            {
                monotones.push_back(std::make_pair(std::vector<Coord>{*e->helper}, std::vector<Coord>{}));
                activeEdges.insert(Edge(prev,event,event, *e->monotonePolygonIndex));
                monotones[*e->monotonePolygonIndex].first.push_back(event);
                *e->monotonePolygonIndex = monotones.size()-1;
            }
            else
            {
                activeEdges.insert(Edge(prev,event,event, indexOfMergeMonotone));
                monotones[indexOfMergeMonotone].first.push_back(event);
            }
            monotones[*e->monotonePolygonIndex].second.push_back(event);
            
            mergeFound = false;
        }
        else if(type == START) 
        {
            std::cout << "Start    " << event.x << "," << event.y << std::endl;
            monotones.push_back(std::make_pair(std::vector<Coord>{event}, std::vector<Coord>{}));
            activeEdges.insert(Edge(prev,event,event,monotones.size()-1));
        }
        else if(type == END) 
        {
            const Edge* e = &(*activeEdges.find(Edge(event,next)));
            if(mergeFound)
            {
                monotones[indexOfMergeMonotone].second.push_back(event);
                mergeFound = false;
            }
            std::cout << "End      " << event.x << "," << event.y << std::endl;
            monotones[*e->monotonePolygonIndex].second.push_back(event);
            activeEdges.erase(Edge(event,next));
        }
        else if (type == REGULAR_UPPER) 
        {
            std::cout << "Upper    " << event.x << "," << event.y << std::endl;
            const Edge* e = &(*activeEdges.find(Edge(event,next)));
            if(mergeFound)
            {
                monotones[*e->monotonePolygonIndex].first.push_back(event);
                mergeFound = false;
            }
            activeEdges.insert(Edge(event,prev,event,*e->monotonePolygonIndex));
            activeEdges.erase(Edge(event,next));
            monotones[*e->monotonePolygonIndex].first.push_back(event);
        }
        else if (type == REGULAR_LOWER) 
        {
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(mergeFound)
            {
                monotones[indexOfMergeMonotone].second.push_back(event);
                mergeFound = false;
            }
            monotones[*e->monotonePolygonIndex].second.push_back(event);
            std::cout << "Lower    " << event.x << "," << event.y << std::endl;
        }
    }

    std::vector<std::vector<Coord>> monotonePolygons;
    for (auto m : monotones)
    {
        std::vector<Coord> newPol;
        for (int i = m.first.size() - 1; i >= 0; --i) 
            newPol.push_back(m.first[i]);
        for (int i = 0 ; i < m.second.size(); ++i) 
            newPol.push_back(m.second[i]);
        monotonePolygons.push_back(newPol);
    }
    return monotonePolygons;
}

bool isConvex(const Coord& prev, const Coord& current, const Coord& next) {
    double crossProduct = (current.x - prev.x) * (next.y - current.y) - (current.y - prev.y) * (next.x - current.x);
    return crossProduct > 0; // Check for counterclockwise direction
}

bool isEar(const Coord& prev, const Coord& current, const Coord& next, const std::vector<Coord>& polygon) {
    if (!isConvex(prev, current, next)) return false;

    for (const Coord& vertex : polygon) {
        if (vertex != prev && vertex != current && vertex != next) {
            double area1 = (next.x - current.x) * (vertex.y - current.y) - (next.y - current.y) * (vertex.x - current.x);
            double area2 = (vertex.x - prev.x) * (next.y - prev.y) - (vertex.y - prev.y) * (next.x - prev.x);
            double area3 = (current.x - vertex.x) * (prev.y - vertex.y) - (current.y - vertex.y) * (prev.x - vertex.x);
            if (area1 >= 0 && area2 >= 0 && area3 >= 0) {
                return false;
            }
        }
    }
    return true;
}

std::vector<Triangle> tessellateMonotonePolygon(const std::vector<Coord>& polygon) {
    std::vector<Triangle> triangles;

    if (polygon.size() < 3) return triangles; // Not a valid polygon

    std::vector<Coord> currentPolygon = polygon;

    while (currentPolygon.size() > 3) {
        size_t n = currentPolygon.size();
        for (size_t i = 0; i < n; ++i) {
            const Coord& prev = currentPolygon[(i + n - 1) % n];
            const Coord& current = currentPolygon[i];
            const Coord& next = currentPolygon[(i + 1) % n];

            if (isEar(prev, current, next, currentPolygon)) {
                triangles.push_back({ prev, current, next });
                currentPolygon.erase(currentPolygon.begin() + i);
                break;
            }
        }
    }

    // Last triangle (final 3 vertices)
    triangles.push_back({ currentPolygon[0], currentPolygon[1], currentPolygon[2] });

    return triangles;
}