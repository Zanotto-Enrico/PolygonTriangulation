#include "headers.hpp"
#include <regex>
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

std::vector<Triangle> getMesh(std::vector<Coord> polygon)
{
  double height = 10;
  //std::vector<Coord> polygon = {{1,1},{14,1},{5,5},{10,10},{1,10}}; 
  //polygon = {{1,2},{5,1},{19,1},{10,5},{15,10},{5,10},{1,9}, {2,4}}; 
  //polygon = {{1,1},{3,4},{1,4},{2,2}}; 
  //polygon = {{0,0},{2,0},{6,4},{2,8},{0,8},{4,4}}; 
  //polygon = {{1,2},{5,1},{19,1},{10,5},{15,10},{5,10},{1,9}, {6,4}}; 
  //polygon = {{1,2},{2,1},{4,2},{6,1},{8,2},{7,4},{5,3}, {3,4}};
  
  std::vector<Triangle> triangles;

  /*std::vector<double> intersections = std::vector<double>();

  for ( int i = polygon.size() - 1; i > 0; --i)
  {
    // generating 2 Triangles for the wall
    triangles.push_back(Triangle{ {polygon[i].x,polygon[i].y,0.0},
                                  {polygon[i].x,polygon[i].y,height},
                                  {polygon[i-1].x,polygon[i-1].y,height}});
    triangles.push_back(Triangle{ {polygon[i-1].x,polygon[i-1].y,0},
                                  {polygon[i-1].x,polygon[i-1].y,height},
                                  {polygon[i].x,polygon[i].y,0}});
  }*/

    for (auto p : partitionPolygonIntoMonotone(polygon))
    {
      for(auto t : triangulateMonotonePolygon(p) )
      {
        triangles.push_back(t);
      }
    }

    return triangles;
}


void getUserInput(std::vector<Coord> &polygon)
{

  std::cout << "Insert the number of vertices: ";
  int numVertices;
  std::cin >> numVertices;

  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the newline from previous input

  std::cout << "Insert a line for each vertex with the format: (x;y)\n";

  std::regex pattern(R"(\((-?\d+(\.\d+)?);(-?\d+(\.\d+)?)\))");

  for (int i = 0; i < numVertices; ++i) {
      std::string input;
      std::cout << "Vertex " << i+1 << ": ";
      std::getline(std::cin, input);

      std::smatch match;
      if (std::regex_match(input, match, pattern)) {
          Coord vertex;
          vertex.x = std::stod(match[1]);
          vertex.y = std::stod(match[3]);
          polygon.push_back(vertex);
      } else {
          std::cout << "Invalid input format. Please use the format (x;y)\n";
          --i; // Repeat the current vertex input
      }
  }
}


int main(int argc, char* argv[])
{

  std::vector<Coord> polygon;

  getUserInput(polygon);

  std::vector<Triangle> triangles = getMesh(polygon);

  //for(int i = 0; i < 1000000; i++)
  for (Triangle triangle : triangles)
  {
    std::cout << "[(" <<  triangle.p1.x << ";" << triangle.p1.y  << 
                 "),(" <<  triangle.p2.x << ";" << triangle.p2.y  <<
                 "),(" <<  triangle.p3.x << ";" << triangle.p3.y  << ")]"<<std::endl;
  }

  return 0;
}