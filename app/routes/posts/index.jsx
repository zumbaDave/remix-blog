import { Link, useLoaderData } from 'remix'
import { db } from '~/utils/db.server'

// loader runs in the server
export const loader = async () => {
    const data = {
        posts: await db.post.findMany({
            select: {id: true, title: true, createdAt: true},
            orderBy: {createdAt: 'desc'}
        })
    }
    return data
}

function PostItem() {
    const {posts} = useLoaderData()

    return (
        <>
            <div className="page-header">
                <h1>Posts</h1>
                <Link to='/posts/new' className='btn'>
                    New Post
                </Link>
            </div>
            
            <ul className="posts-list">
                {posts.map((post) => (
                    <li key={post.id}>
                        <Link to={post.id}>
                            <h3>{post.title}</h3>
                            {new Date(post.createdAt).toLocaleString()}
                        </Link>
                    </li>
                ))}
            </ul>
        </>
    )
}

export default PostItem