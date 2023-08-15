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

    return nullptr;  
}

vertexType getVertexType(const Coord &vertex, const Coord &next, const Coord &prev )
{
    if(prev.x == vertex.x && vertex.x == next.x)
        return VERTICAL;
    if(prev.x <= vertex.x && next.x <= vertex.x)
    {
        Coord vector_pc = {vertex.x - prev.x, vertex.y - prev.y, 0.0, 0};
        Coord vector_pn = {next.x - prev.x, next.y - prev.y, 0.0, 0};
        double cross_product = vector_pc.x * vector_pn.y - vector_pc.y * vector_pn.x; // cross product between 2 vectors
        
        if(cross_product < 0)   return MERGE;
        else                    return END;
    }
    
    if(prev.x >= vertex.x && next.x >= vertex.x)
    {
        Coord vector_pc = {vertex.x - prev.x, vertex.y - prev.y, 0.0, 0};
        Coord vector_pn = {next.x - prev.x, next.y - prev.y, 0.0, 0};
        double cross_product = vector_pc.x * vector_pn.y - vector_pc.y * vector_pn.x; // cross product between 2 vectors
        
        if(cross_product < 0)   return SPLIT;
        else                    return START;
    }
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
            if(*e->mergeMonotonePolygonIndex != -1)
            {
                monotones[*e->mergeMonotonePolygonIndex].first.push_back(event);
            }
            if(e)
                e->helper->x = event.x; e->helper->y = event.y; e->helper->z = event.z; e->helper->index = event.index; 
            
            monotones[*e->monotonePolygonIndex].second.push_back(event);
            *e->mergeMonotonePolygonIndex = *activeEdges.find(Edge(event,next))->monotonePolygonIndex;
            monotones[*e->mergeMonotonePolygonIndex].first.push_back(event);
            activeEdges.erase(Edge(event,next));
        }
        else if (type == SPLIT) 
        {

            std::cout << "Split    " << event.x << "," << event.y << std::endl;
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(*e->mergeMonotonePolygonIndex == -1)
            {
                monotones.push_back(std::make_pair(std::vector<Coord>{*e->helper}, std::vector<Coord>{}));
                activeEdges.insert(Edge(prev,event,event, *e->monotonePolygonIndex));
                monotones[*e->monotonePolygonIndex].first.push_back(event);
                *e->monotonePolygonIndex = monotones.size()-1;
            }
            else
            {
                activeEdges.insert(Edge(prev,event,event, *e->mergeMonotonePolygonIndex));
                monotones[*e->mergeMonotonePolygonIndex].first.push_back(event);
            }
            monotones[*e->monotonePolygonIndex].second.push_back(event);
            
            *e->mergeMonotonePolygonIndex = -1;
        }
        else if(type == START) 
        {
            std::cout << "Start    " << event.x << "," << event.y << std::endl;

            Coord it = event;
            if(it.x == prev.x)  //start-down point
            {
                while(it.x == prev.x)
                {
                    it = prev;
                    prev = polygon[(prev.index + vertices_num - 1)%vertices_num];
                }
                auto bound = activeEdges.find(Edge(it, prev));
                if(bound == activeEdges.end()){
                    monotones.push_back(std::make_pair(std::vector<Coord>{event}, std::vector<Coord>{}));
                    activeEdges.insert(Edge(prev,it,it,monotones.size()-1));
                }
                else
                    monotones[*bound->monotonePolygonIndex].second.push_back(event);

            }
            else if(it.x == next.x) //start-upper point
            {
                auto bound = activeEdges.find(Edge(it, prev));
                if(bound == activeEdges.end()){
                    monotones.push_back(std::make_pair(std::vector<Coord>{event}, std::vector<Coord>{}));
                    activeEdges.insert(Edge(prev,it,it,monotones.size()-1));
                }
                else
                    monotones[*bound->monotonePolygonIndex].first.push_back(event);
            }
            else
            {
                monotones.push_back(std::make_pair(std::vector<Coord>{event}, std::vector<Coord>{}));
                activeEdges.insert(Edge(prev,it,it,monotones.size()-1));
            }
            
        }
        else if(type == END) 
        {
            auto near = activeEdges.find(Edge(event,next));
            if( near == activeEdges.end())// if there is no near edge, that edge is vertical
            {
                const Edge* e = findUpperBound(event.y,event.x, activeEdges);
                if(*e->mergeMonotonePolygonIndex != -1)
                {
                    monotones[*e->mergeMonotonePolygonIndex].second.push_back(event);
                    *e->mergeMonotonePolygonIndex = -1;
                }
                std::cout << "End      " << event.x << "," << event.y << std::endl;
                monotones[*e->monotonePolygonIndex].second.push_back(event);
            }
            else
            {
                if(*near->mergeMonotonePolygonIndex != -1)
                {
                    monotones[*near->mergeMonotonePolygonIndex].second.push_back(event);
                    *near->mergeMonotonePolygonIndex = -1;
                }
                std::cout << "End      " << event.x << "," << event.y << std::endl;
                monotones[*near->monotonePolygonIndex].second.push_back(event);
                activeEdges.erase(Edge(event,next)); 
            }
        }

        if (type == REGULAR_UPPER) 
        {
            std::cout << "Upper    " << event.x << "," << event.y << std::endl;
            const Edge* e = &(*activeEdges.find(Edge(event,next)));
            if(*e->mergeMonotonePolygonIndex != -1)
            {
                monotones[*e->monotonePolygonIndex].first.push_back(event);
                *e->mergeMonotonePolygonIndex = -1;
            }
            activeEdges.insert(Edge(event,prev,event,*e->monotonePolygonIndex));
            activeEdges.erase(Edge(event,next));
            monotones[*e->monotonePolygonIndex].first.push_back(event);
        }
        
        if (type == REGULAR_LOWER) 
        {
            const Edge* e = findUpperBound(event.y,event.x, activeEdges);
            if(*e->mergeMonotonePolygonIndex != -1)
            {
                monotones[*e->mergeMonotonePolygonIndex].second.push_back(event);
                *e->mergeMonotonePolygonIndex = -1;
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
            while ( (( current.y > last.y && type==REGULAR_LOWER ) || ( current.y < last.y && type==REGULAR_UPPER )) && deque.size() > 1)
            {
                last = deque.front();
                deque.pop_front();
                triangles.push_back({deque.front(),last,current});
                
            }
            deque.push_front(current);
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