#include <vector>
#include <utility>
#include <iostream>
#include <math.h>
#include <algorithm>
#include <set>
#include <queue>
#include <stack>
#include <utility>
#include <list>

/*                        ^
*                         |0
*                         |
*  10      * * * * * * * *|* * 
*          *              | *
*          *              | 
*          *            * |
*          *          *   |
*  5       *         *    |
*          *            * |
*          *              | *
*          *              |     *
*  1       * * * * * * * *|* * * * * 
*                         |
*                         |6 
*          1       5        10        15     
*/

struct Coord
{
  double x;
  double y;
  double z;
    // Comparison operator for sorting vertices based on x-coordinate.
    bool operator<(const Coord& other) const
    {
        return x < other.x;
    }

};



struct Triangle {
    Coord p1;
    Coord p2;
    Coord p3;
};

struct mySegment {
    Coord p1;
    Coord p2;
};


Coord crossProduct(const Coord& v1, const Coord& v2) {
    Coord result;
    result.x = v1.y * v2.z - v1.z * v2.y;
    result.y = v1.z * v2.x - v1.x * v2.z;
    result.z = v1.x * v2.y - v1.y * v2.x;
    return result;
}

// Funzione per calcolare il prodotto scalare tra due vettori
double dotProduct(const Coord& v1, const Coord& v2) {
    return v1.x * v2.x + v1.y * v2.y + v1.z * v2.z;
}

// Funzione per calcolare la lunghezza di un vettore
double vectorLength(const Coord& vector) {
    return std::sqrt(vector.x * vector.x + vector.y * vector.y + vector.z * vector.z);
}

// Funzione per calcolare l'intersezione tra un mySegmento e un triangolo in 3 dimensioni
double intersectmySegmentTriangle(const mySegment& mySegment, const Triangle& triangle) {
    Coord edge1, edge2, mySegmentVector, h, s, q;
    double a, f, u, v, t;

    edge1.x = triangle.p2.x - triangle.p1.x;
    edge1.y = triangle.p2.y - triangle.p1.y;
    edge1.z = triangle.p2.z - triangle.p1.z;

    edge2.x = triangle.p3.x - triangle.p1.x;
    edge2.y = triangle.p3.y - triangle.p1.y;
    edge2.z = triangle.p3.z - triangle.p1.z;

    mySegmentVector.x = mySegment.p2.x - mySegment.p1.x;
    mySegmentVector.y = mySegment.p2.y - mySegment.p1.y;
    mySegmentVector.z = mySegment.p2.z - mySegment.p1.z;

    // vettore normale del piano generato dal vettore del segmento e di un lato del triangolo
    h = crossProduct(mySegmentVector, edge2);
    // prodotto scalare tra la normale e un altro lato del triangolo
    a = dotProduct(edge1, h);
    // se il prodotto scalare è molto vicino allo zero allora il vettore è parallelo al triangolo
    if (a > -0.00001 && a < 0.00001) {
        return -1; 
    }


    f = 1 / a;
    s.x = mySegment.p1.x - triangle.p1.x;
    s.y = mySegment.p1.y - triangle.p1.y;
    s.z = mySegment.p1.z - triangle.p1.z;

    // prima coordinata baricentrica
    u = f * dotProduct(s, h);

    if (u < 0 || u > 1) {
        return -1; // L'intersezione si trova fuori 
    }

    q = crossProduct(s, edge1);
    // seconda coordinata baricentrica
    v = f * dotProduct(mySegmentVector, q);

    if (v < 0 || u + v > 1) {
        return -1; // L'intersezione si trova fuori 
    }

    t = f * dotProduct(edge2, q);

    if (t > 0 && t < 1) {
        return t; // L'intersezione si trova all'interno 
    }

    return -1; // L'intersezione si trova fuori 
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct Edge
{
    Coord start;
    Coord end;
    size_t index;


    Coord helper; // sweep line helper vertex
    // Comparison operator for sorting edge events based on y-coordinate.
    bool operator<(const Edge& other) const
    {
        return start.y < other.start.y;
    }
};

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

void partitionPolygonIntoMonotone(const std::vector<Coord>& polygon)
{
    // Step 1: Create edges from the input vertices and sort them based on x-coordinate.
    std::vector<Edge> edges;
    for (size_t i = 0; i < polygon.size(); ++i)
    {
        size_t next = (i + 1) % polygon.size();
        if (polygon[i].x < polygon[next].x)
            edges.push_back({polygon[i], polygon[next], i});
        else
            edges.push_back({polygon[next], polygon[i], i});
    }
    int edges_num = edges.size();
    
    // Step 2: Create the event queue and initialize it with vertex and edge events.
    std::vector<Edge> eventQueue = edges;
    std::sort(eventQueue.begin(), eventQueue.end());

    // Step 3: Initialize the status data structure (e.g., a binary search tree).
    std::vector<Edge> newEdges;

    // Sweep line partitions boundaries
    std::set<Edge> activeEdges;

    for (const Edge& event : eventQueue)
    {

        Edge prev = edges[(event.index+edges_num-1)%edges_num];
        Edge next = edges[(event.index+1)%edges_num];

        // Determine whether this is a merge vertex, split vertex, or regular vertex.
        bool isMerge = (event.start.y < event.end.y )  && prev.start.x < event.end.x &&     event.end.x == prev.end.x && event.end.y == prev.end.y;
        bool isEnd   = (event.start.y < event.end.y )  && next.start.x < event.end.x &&     event.end.x == next.end.x && event.end.y == next.end.y;
        bool isSplit = (event.start.y > event.end.y )  && next.end.x > event.start.x &&     event.start.x == next.start.x && event.start.y == next.start.y;
        bool isStart = (event.start.y > event.end.y )  && prev.end.x > event.start.x &&     event.start.x == prev.start.x && event.start.y == prev.start.y;
        bool isRegularUpper = !isMerge && !isEnd && !isSplit && !isStart && next.end.x == event.start.x && next.end.y == event.start.y;
        bool isRegularLower = !isMerge && !isEnd && !isSplit && !isStart && next.start.x == event.end.x && next.start.y == event.end.y;

        if (isMerge) // Handle merge vertices 
        {
            std::cout << "Merge    " << event.end.x << "," << event.end.y << std::endl;
            activeEdges.erase(event);
            activeEdges.erase(prev);
        }
        if (isSplit) // Handle split vertices 
        {

            std::cout << "Split    " << event.start.x << "," << event.start.y << std::endl;

            // adding new diagonal from the split vertex to the helper
            const Edge* e = findUpperBound(event.start.y,event.start.x, activeEdges);
            if(e)
                newEdges.push_back({{event.start.x,event.start.y,event.start.z},{e->helper.x,e->helper.y,e->helper.z}});
            
            activeEdges.insert(event);
            activeEdges.insert(next);
        }
        if(isStart) 
        {
            std::cout << "Start    " << event.start.x << "," << event.start.y << std::endl;
            activeEdges.insert(event);
            activeEdges.insert(prev);
        }
        if(isEnd) 
        {
            std::cout << "End      " << event.end.x << "," << event.end.y << std::endl;
            activeEdges.erase(event);
            activeEdges.erase(next);
        }
        if (isRegularUpper) 
        {
            std::cout << "Upper      " << event.start.x << "," << event.start.y << std::endl;
        }
        if (isRegularLower) 
        {
            std::cout << "Lower      " << event.end.x << "," << event.end.y << std::endl;
        }
    }

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::vector<Triangle> getMesh()
{
  double height = 10;
  std::vector<Coord> polygon = {{1,1},{14,1},{5,5},{10,10},{1,10}}; 
  polygon = {{1,2},{5,1},{19,1},{10,5},{15,10},{5,10},{1,9}, {2,4}}; 
  //polygon = {{1,1},{2,2},{1,3}}; 
  
  std::vector<Triangle> triangles;

  std::vector<double> intersections = std::vector<double>();

  for ( int i = polygon.size() - 1; i > 0; --i)
  {
    // generating 2 Triangles for the wall
    triangles.push_back(Triangle{ {polygon[i].x,polygon[i].y,0.0},
                                  {polygon[i].x,polygon[i].y,height},
                                  {polygon[i-1].x,polygon[i-1].y,height}});
    triangles.push_back(Triangle{ {polygon[i-1].x,polygon[i-1].y,0},
                                  {polygon[i-1].x,polygon[i-1].y,height},
                                  {polygon[i].x,polygon[i].y,0}});
  }


    // Stampa i triangoli
    
    partitionPolygonIntoMonotone(polygon);


  return triangles;
}



int main(int argc, char* argv[])
{

  std::vector<Triangle> triangles = getMesh();

  Coord from = {9,0,6};
  Coord to = {9,12,0};

  //for(int i = 0; i < 1000000; i++)
  for (Triangle triangle : triangles)
  {
    double intersection = intersectmySegmentTriangle({to, from}, triangle);
    if (intersection == -1) {
        //std::cout << "Il mySegmento non interseca il triangolo." << std::endl;
    } else {
        std::cout << "Il mySegmento interseca il triangolo. Posizione: " << intersection << std::endl;
    }
  }

  return 0;
}