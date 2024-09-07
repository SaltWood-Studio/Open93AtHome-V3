import Database from 'better-sqlite3';
import { ClusterEntity } from './database/Cluster.js';

// 表的定义映射
const tableSchemaMap = new Map<Function, string>();

// 装饰器用于指定表名和表结构
function Table(tableName: string, schema: string) {
    return function (constructor: Function) {
        tableSchemaMap.set(constructor, schema);
    };
}

const primaryKeyMap = new Map<Function, string>();

function PrimaryKey(tableName: string) {
    return function (constructor: Function) {
        primaryKeyMap.set(constructor, tableName);
    };
}

function Ignore() {
    return function (target: any, propertyName: string) {
        const constructor = target.constructor;
        if (!constructor.ignoredFields) {
            constructor.ignoredFields = [];
        }
        constructor.ignoredFields.push(propertyName);
    };
}

export { Table, Ignore, PrimaryKey };

export class SQLiteHelper {
    private db: Database.Database;

    constructor(private dbFilePath: string) {
        // 打开数据库连接
        this.db = new Database(dbFilePath, { verbose: console.log });
    }

    // 创建表
    public createTable<T>(type: { new (): T }): void {
        const tableName = this.getTableNameByConstructor(type);
        const schema = tableSchemaMap.get(type);
        if (!schema) {
            throw new Error(`Schema for table ${tableName} not defined`);
        }
        const createTableSQL = `CREATE TABLE IF NOT EXISTS ${tableName} (${schema})`;
        this.db.exec(createTableSQL);
    }

    public insert<T extends object>(obj: T): void {
        const tableName = this.getTableName(obj);
        const data = obj as Record<string, any>;
        const ignoredFields = (obj.constructor as any).ignoredFields || [];
        const kvp = Object.keys(data).filter(key => !ignoredFields.includes(key));
    
        const columns = kvp.join(', ');
        const placeholders = kvp.map(() => '?').join(', '); // 添加占位符
        const values = kvp.map(key => data[key]); // 取得对应的值
    
        const insertSQL = `INSERT INTO ${tableName} (${columns}) VALUES (${placeholders})`;
        const stmt = this.db.prepare(insertSQL);
        stmt.run(...values); // 使用展开运算符传递值
    }    

    // 查询数据
    public select<T>(type: { new (): T }, columns: string[], whereClause?: string, params?: any[]): T[] {
        const tableName = this.getTableNameByConstructor(type);
        const selectSQL = `SELECT ${columns.join(', ')} FROM ${tableName} ${whereClause ? `WHERE ${whereClause}` : ''}`;
        const stmt = this.db.prepare(selectSQL);
        return (stmt.all(params) as T[]);
    }

    public getEntity<T extends object>(type: { new (): T }, primaryKey: number | string): T | null {
        const tableName = this.getTableNameByConstructor(type);
        const pk = primaryKeyMap.get(type.constructor as { new (): T }) || 'id';
        const selectSQL = `SELECT * FROM ${tableName} WHERE ${pk} = ?`;
        const stmt = this.db.prepare(selectSQL);
        const row = stmt.get(primaryKey);

        if (row) {
            const entity = new type();
            Object.assign(entity, row);
            return entity;
        }
        
        return null; // 如果找不到记录，返回 null
    }
    
    public getEntities<T extends object>(type: { new (): T }): T[] {
        const tableName = this.getTableNameByConstructor(type);
        const selectSQL = `SELECT * FROM ${tableName}`;
        const stmt = this.db.prepare(selectSQL);
        const rows = (stmt.all() as T[]);
    
        return rows.map((row: T) => {
            const entity = new type();
            Object.assign(entity, row);
            return entity;
        });
    }

    public update<T extends object>(obj: T): void {
        const tableName = this.getTableName(obj);
        const data = obj as Record<string, any>;
        const ignoredFields = (obj.constructor as any).ignoredFields || [];

        const pk = primaryKeyMap.get(obj.constructor as { new (): T }) || 'id';
        if (!pk) {
            throw new Error(`Primary key for table ${tableName} not defined`);
        }
        const kvp = Object.keys(data).filter(key => key !== pk && !ignoredFields.includes(key));
    
        // Construct the update columns, ignoring fields marked with @ignore
        const columns = kvp.map(key => `${key} = ?`).join(', ');
    
        const values = kvp.map(key => data[key]);
    
        // Ensure `id` is at the end of the values array
        values.push(data[pk]);
    
        const updateSQL = `UPDATE ${tableName} SET ${columns} WHERE ${pk} = ?`;
        const stmt = this.db.prepare(updateSQL);
        stmt.run(values);
    }    

    public remove<T extends object>(type: { new (): T }, primaryKey: number | string): void {
        const tableName = this.getTableNameByConstructor(type);
        const pk = primaryKeyMap.get(type.constructor as { new (): T }) || 'id';
        const deleteSQL = `DELETE FROM ${tableName} WHERE ${pk} = ?`;
        const stmt = this.db.prepare(deleteSQL);
        stmt.run(primaryKey);
    }    

    private getTableName<T>(obj: T): string {
        const constructor = (obj as Object).constructor;
        return this.getTableNameByConstructor(constructor as { new (): T });
    }

    // 根据类型推断表名
    private getTableNameByConstructor<T>(type: { new (): T }): string {
        const constructor = type;
        return constructor.name.toLowerCase() + 's';
    }

    // 关闭数据库连接
    public close(): void {
        this.db.close();
    }
}
