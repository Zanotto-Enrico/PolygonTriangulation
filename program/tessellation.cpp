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


std::vector<Triangle> triangulateMonotonePolygon(const std::vector<Coord>& polygon) {
    std::vector<Triangle> triangles;
    int poly_len = polygon.size();

    if(poly_len < 3 ) return  std::vector<Triangle>();
    
    //////
    std::vector<Coord> eventQueue = polygon;
    for (size_t i = 0; i < polygon.size(); ++i)
        eventQueue[i].index = i;
    std::sort(eventQueue.begin(), eventQueue.end());
    std::deque<Coord> deque;
    deque.push_front(eventQueue[0]);
    deque.push_front(eventQueue[1]);
    //////
/*
    // obtaining the first vertex 
    int first = 0;
    for(int i = 1; i < poly_len; i++)
        if(polygon[first].x > polygon[i].x)   first = i;

    std::stack<Coord> stack;
    stack.push(polygon[first]);
    stack.push(polygon[(first+1)%poly_len]);
*/
    for (int i = 2; i < poly_len; ++i)
    {
        Coord current = eventQueue[i];
        Coord prev = polygon[(current.index+poly_len-1)%poly_len];
        Coord next = polygon[(current.index+1)%poly_len];

        Coord last = deque.front();
        vertexType lastType = getVertexType(last, polygon[(last.index+1)%poly_len], polygon[(last.index+poly_len-1)%poly_len]);

        vertexType type = getVertexType(current,next,prev);
        if(type == lastType)
        {
            deque.push_front(current);
            if (current.y > last.y)
            {
                deque.pop_front();
                deque.pop_front();
                triangles.push_back({deque.front(),last,current});
                deque.push_front(current);
            }
        }
        else
        {
            Coord tmp = deque.back();
            deque.pop_back();
            while(deque.size() >= 2)
            {
                triangles.push_back({tmp,current,deque.back()});
                tmp = deque.back();          //
                deque.pop_back();                // no devi prendere da sotto!!!!!!!!
            }
            triangles.push_back({tmp,current,deque.back()});
            deque.push_front(current);
        }   
    }

    return triangles;
}