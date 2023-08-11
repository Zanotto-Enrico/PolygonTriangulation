#include "headers.hpp"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*                        ^
*                         |0
*                         |
*  10                * * *|* * * *
*          * * * * *      |    *
*           *             |   *
*            *            |  *
*              *          |    *
*  5          *           |      *   
*            *            |         * 
*           *             |           *
*          ***            |              *
*  1          * * * * * * * * * * * * * * * * 
*                         |
*                         |6 
*          1       5        10        15     
*/


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::vector<Triangle> getMesh()
{
  double height = 10;
  std::vector<Coord> polygon = {{1,1},{14,1},{5,5},{10,10},{1,10}}; 
  polygon = {{1,2},{5,1},{19,1},{10,5},{15,10},{5,10},{1,9}, {2,4}}; 
  //polygon = {{1,1},{3,4},{1,4},{2,2}}; 
  //polygon = {{0,0},{2,0},{6,4},{2,8},{0,8},{4,4}}; 
  //polygon = {{1,2},{5,1},{19,1},{10,5},{15,10},{5,10},{1,9}, {6,4}}; 
  
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

    for (auto p : partitionPolygonIntoMonotone(polygon))
    {
        std::cout << "Monotone polygon: ";
        for(auto v : p)
        {
            std::cout  <<"(" << v.x << ";" << v.y << ")  "; 
        }
        std::cout << "\n";
        for(auto t : triangulateMonotonePolygon(p) )
        {
            std::cout  <<"   Triangle: (" << t.p1.x << ";" << t.p1.y << ")  (" << t.p2.x << ";" << t.p2.y << ")  (" << t.p3.x << ";" << t.p3.y << ")\n"; 
        }
    }

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