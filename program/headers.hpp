#include <vector>
#include <utility>
#include <iostream>
#include <math.h>
#include <algorithm>
#include <set>
#include <list>
#include <map>
#include <deque>

struct Coord
{
  double x;
  double y;
  double z;
  size_t index;
    // Comparison operator for sorting vertices based on x-coordinate.
    bool operator<(const Coord& other) const
    {
        return x < other.x || (x == other.x && y < other.y) ;
    }

    bool operator==(const Coord& other) const 
    {
        return x == other.x &&  y == other.y && z == other.z;
    }

    bool operator!=(const Coord& other) const 
    {
        return !(*this == other);
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

class Edge
{
public:
    Coord start;
    Coord end;
    
    Coord* helper; // sweep line helper vertex
    int* monotonePolygonIndex; // index of the relative monotone polygon  
    int* mergeMonotonePolygonIndex; // index of the relative monotone polygon of the last seen merge vertex

    Edge() {
        helper = new Coord;
        monotonePolygonIndex = new int(-1);
        mergeMonotonePolygonIndex = new int(-1);
    }

    Edge(const Coord& vertex1, const Coord& vertex2) : Edge() {
        if (vertex1.x < vertex2.x) {
            start = vertex1;
            end = vertex2;
        } else {
            start = vertex2;
            end = vertex1;
        }
    }
    Edge(const Coord& vertex1, const Coord& vertex2, const Coord& help) : Edge(vertex1,vertex2) 
    {    
        *helper = help;
    }
    Edge(const Coord& vertex1, const Coord& vertex2, const Coord& help, int index) : Edge(vertex1,vertex2,help) 
    {    
        *monotonePolygonIndex = index;
    }

    // Comparison operator for sorting edge events based on y-coordinate.
    bool operator<(const Edge& other) const
    {
        if(this->start.x == other.start.x && this->end.x == other.end.x && 
           this->start.y == other.start.y && this->end.y == other.end.y)
            return false;
        double thisMinY = std::min(start.y, end.y);
        double thisMaxY = std::max(start.y, end.y);

        double otherMinY = std::min(other.start.y, other.end.y);
        double otherMaxY = std::max(other.start.y, other.end.y);
        if (thisMaxY <= otherMinY) {
            return true;
        } else if (thisMinY >= otherMaxY) {
            return false;
        } else {
            if(start.x != other.start.x)
                return start.x > other.start.x;
            else
                return end.x > other.end.x;
        }
    }
    bool operator==(const Edge& other) const {
        return start == other.start && end == other.end;
    }
    bool operator!=(const Edge& other) const {
        return !(*this == other);
    }
    

};

int arc_length(int i, int j, int N);

struct LessPredicate {
    int N; // Number of vertices in the polygon
    LessPredicate(int numVertices) : N(numVertices) {}

    bool operator()(const Edge& diag1, const Edge& diag2) const {
        int arcLenDiag1 = arc_length(diag1.start.index, diag1.end.index, N);
        int arcLenDiag2 = arc_length(diag2.start.index, diag2.end.index, N);
        return arcLenDiag1 < arcLenDiag2;
    }
};

enum vertexType { START, END, MERGE, SPLIT, REGULAR_UPPER, REGULAR_LOWER, VERTICAL};



/* tassellation.cpp */

const Edge* findUpperBound(double y,double x, std::set<Edge> &bounds);
std::vector<std::vector<Coord>> partitionPolygonIntoMonotone(std::vector<Coord>& polygon);
std::vector<Triangle> triangulateMonotonePolygon(const std::vector<Coord>& polygon);
vertexType getVertexType(const Coord &vertex, const Coord &next, const Coord &prev );
bool isCounterClockwise(const std::vector<Coord>& vertices);

/* algebra.cpp */

Coord crossProduct(const Coord& v1, const Coord& v2);
double dotProduct(const Coord& v1, const Coord& v2);
double vectorLength(const Coord& vector);
double intersectmySegmentTriangle(const mySegment& mySegment, const Triangle& triangle);