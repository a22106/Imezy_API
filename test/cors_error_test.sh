curl -H "Origin: http://localhost" \
-H "Access-Control-Request-Method: GET" \
-H "Access-Control-Request-Headers: X-Requested-With" \
-H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImJrMjIxMDZAZ21haWwuY29tIiwidXNlcl9pZCI6MSwiZXhwIjoxNjcwNDA2MTg5fQ.h8jf4er9qgvwo7N0Le2gqRe78TT-Mq5OICHCnHgj5no" \
--verbose "http://133.186.213.110:7860/user/read_users"