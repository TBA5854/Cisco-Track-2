def get_tableData():
  # Replace this with your logic to fetch and process data
  # This example returns a list of dictionaries representing rows
  data = [
      {"name": "John Doe", "h":1,"age": 30, "city": "New York"},
      {"name": "John Doe", "h":2,"age": 30, "city": "New York"},
      {"name": "John Doe", "h":3,"age": 30, "city": "New York"},
      {"name": "Jane Smith", "h":1,"age": 25, "city": "London"},
  ]
  return data

# import flask
# Import Flask and render_template from Flask
from flask import Flask, render_template

# Create a Flask application instance
app = Flask(__name__)

# Define the route for the table view
@app.route("/")
def table_view():
  table_data = get_tableData()
  return render_template(r"table.html", data=table_data)

# Run the Flask development server
if __name__ == "__main__":
  app.run(debug=True)
