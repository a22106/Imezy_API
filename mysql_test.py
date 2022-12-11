import pymysql

# mysql connection
conn = pymysql.connect(host='imezy.cfrm6ylsjgcg.ap-northeast-2.rds.amazonaws.com', port=3306, user='admin', password="imezy2022!",
                       db='imezy', charset='utf8', # utf8: 한글깨짐 방지
                       autocommit=True, cursorclass=pymysql.cursors.DictCursor
)

# connection 으로부터 cursor 생성
cur = conn.cursor()

# sql문 실행 및 fetch
sql = 'select * from users;'
cur.execute(sql)
rows = cur.fetchall()
conn.close()
for col in rows:
    print(col)