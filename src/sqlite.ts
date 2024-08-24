import Database from 'better-sqlite3';
import { ClusterEntity } from './database/cluster';

// 表的定义映射
const tableSchemaMap = new Map<Function, string>();

// 装饰器用于指定表名和表结构
function Table(tableName: string, schema: string) {
    return function (constructor: Function) {
        tableSchemaMap.set(constructor, schema);
    };
}

function Ignore(und: undefined, {name}: {name: string}) {
    return function (this: any, value: any) {
        if (!this.constructor.ignoredFields) {
            this.constructor.ignoredFields = [];
        }
        this.constructor.ignoredFields.push(name);
        return value;
    };
}

export { Table, Ignore };

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

    // 插入数据
    public insert<T>(obj: T): void {
        const tableName = this.getTableName(obj);
        const data = obj as Record<string, any>;
        const columns = Object.keys(data).join(', ');
        const placeholders = Object.keys(data).map(() => '?').join(', ');
        const values = Object.values(data);

        const insertSQL = `INSERT INTO ${tableName} (${columns}) VALUES (${placeholders})`;
        const stmt = this.db.prepare(insertSQL);
        stmt.run(values);
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
        const selectSQL = `SELECT * FROM ${tableName} WHERE id = ?`;
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
    
        // Construct the update columns, ignoring fields marked with @ignore
        const columns = Object.keys(data)
            .filter(key => key !== 'id' && !ignoredFields.includes(key))
            .map(key => `${key} = ?`).join(', ');
    
        const values = Object.keys(data)
            .filter(key => key !== 'id' && !ignoredFields.includes(key))
            .map(key => data[key]);
    
        // Ensure `id` is at the end of the values array
        values.push(data.id);
    
        const updateSQL = `UPDATE ${tableName} SET ${columns} WHERE id = ?`;
        const stmt = this.db.prepare(updateSQL);
        stmt.run(values);
    }    

    public remove<T extends object>(type: { new (): T }, primaryKey: number | string): void {
        const tableName = this.getTableNameByConstructor(type);
        const deleteSQL = `DELETE FROM ${tableName} WHERE id = ?`;
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
