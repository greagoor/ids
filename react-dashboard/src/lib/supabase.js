import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || ''
const supabaseKey = import.meta.env.VITE_SUPABASE_KEY || ''

export const supabase = createClient(supabaseUrl, supabaseKey)
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
