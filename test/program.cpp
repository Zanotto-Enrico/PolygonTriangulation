//#define CGAL_EIGEN3_ENABLED
#include <CGAL/Exact_predicates_exact_constructions_kernel.h>
#include <CGAL/poisson_surface_reconstruction.h>
#include <CGAL/intersections.h>
#include <CGAL/Surface_mesh/Surface_mesh.h>
#include <CGAL/Point_set_3/IO/XYZ.h>
#include <CGAL/Point_set_3.h>
#include <vector>
#include <utility>
#include <iostream>
#include <math.h>


typedef CGAL::Exact_predicates_exact_constructions_kernel K;
typedef K::Point_3 Point;
typedef K::Segment_3 Segment;
typedef K::Intersect_3 Intersect;
typedef K::Triangle_3 Triangle;
typedef CGAL::Point_set_3<Point> Point_set;
typedef CGAL::Surface_mesh<Point> Surface_mesh;

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
};


std::vector<Triangle> getMesh()
{
  int height = 10;
  std::vector<Coord> polygon = {{1,1},{14,1},{5,5},{10,10},{1,10},{1,1}}; 
  
  Coord from = {9,0,6};
  Coord to = {9,12,0};
  
  std::vector<Triangle> triangles;

  std::vector<double> intersections = std::vector<double>();

  for ( int i = polygon.size() - 2; i > 1; --i)
  {
    // generating a floor triangle
    triangles.push_back(Triangle( Point(polygon[i].x,polygon[i].y,0),
                                  Point(polygon[i-1].x,polygon[i-1].y,0),
                                  Point(polygon[0].x,polygon[0].y,0)));
    // generating a roof triangle
    triangles.push_back(Triangle( Point(polygon[i].x,polygon[i].y,height),
                                  Point(polygon[i-1].x,polygon[i-1].y,height),
                                  Point(polygon[0].x,polygon[0].y,height)));
  }
  for ( int i = polygon.size() - 1; i > 0; --i)
  {
    // generating 2 triangles for the wall
    triangles.push_back(Triangle( Point(polygon[i].x,polygon[i].y,0),
                                  Point(polygon[i].x,polygon[i].y,height),
                                  Point(polygon[i-1].x,polygon[i-1].y,height)));
    triangles.push_back(Triangle( Point(polygon[i-1].x,polygon[i-1].y,0),
                                  Point(polygon[i-1].x,polygon[i-1].y,height),
                                  Point(polygon[i].x,polygon[i].y,0)));
  }

  return triangles;
}



int main(int argc, char* argv[])
{
  Coord from = {9,0,6};
  Coord to = {9,12,0};
  
  std::vector<Triangle> triangles = getMesh();
  // segment object
  Segment seg(Point(from.x,from.y,from.z), Point(to.x,to.y,to.z));
  // segment length
  double segLen = std::pow( std::pow(to.x - from.x, 2) + 
                            std::pow(to.y - from.y, 2) + 
                            std::pow(to.z - from.z, 2), 1.0/2.0);

  //for(int i = 0; i < 1000000; i++)
  for (Triangle triangle : triangles) 
  {
    const auto result = intersection(seg, triangle);               // interect segment with a triangle
    if (result) {
      if (const Segment* s = boost::get<Segment>(&*result))               // if the result is a segment
      {
        //std::cout << "segment: " << *s << std::endl;
      } else                                                              // if the result is a point
      {
        const Point* p = boost::get<Point>(&*result);
        
        double intersection = std::pow( std::pow(to.x - CGAL::to_double((*p).x()), 2) + 
                                                    std::pow(to.y - CGAL::to_double((*p).y()), 2) + 
                                                    std::pow(to.z - CGAL::to_double((*p).z()), 2), 1.0/2.0)/segLen;
        std::cout << "intersection: " << intersection << std::endl;
      }
    }
  }

  return 0;
}